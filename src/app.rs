use crate::updater::distribution::{self, ReleaseInfo, ReleaseServer, UpdateAnnouncement};
use crate::{
    config::AppConfig,
    core::{self, FileInspection, TransferControl, TransferEngine},
    gui::{self, Screen},
    hardware::HardwareSnapshot,
    network::{
        self, DiscoveryAnnouncement, DiscoveryEvent, DiscoveryHandle, TransferDirection,
        TransferEvent, TransferSecurity,
    },
    security::DeviceIdentity,
    storage::{database, SavedFriend},
    updater::{self, UpdateCandidate, UpdateEvent, UpdateWatcher},
};
use eframe::egui;
use std::{
    collections::{HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{runtime::Runtime, sync::mpsc};
use tracing::{error, info};

struct HashResult {
    path: PathBuf,
    result: Result<String, String>,
}

struct PendingApproval {
    direction: TransferDirection,
    transfer_id: String,
    device_id: String,
    device_name: String,
    operating_system: String,
    certificate_fingerprint: String,
    peer: String,
    responder: tokio::sync::oneshot::Sender<bool>,
}

struct NetworkUpdate {
    announcement: UpdateAnnouncement,
    address: SocketAddr,
    release: ReleaseInfo,
}

pub struct RussApp {
    config: AppConfig,
    identity: DeviceIdentity,
    screen: Screen,
    hardware: HardwareSnapshot,
    engine: TransferEngine,
    sender: gui::sender::SenderState,
    receiver: gui::receiver::ReceiverState,
    status: String,
    runtime: Arc<Runtime>,
    hash_tx: mpsc::UnboundedSender<HashResult>,
    hash_rx: mpsc::UnboundedReceiver<HashResult>,
    event_tx: mpsc::UnboundedSender<TransferEvent>,
    event_rx: mpsc::UnboundedReceiver<TransferEvent>,
    discovery: Option<DiscoveryHandle>,
    discovery_rx: mpsc::UnboundedReceiver<DiscoveryEvent>,
    _update_watcher: Option<UpdateWatcher>,
    update_rx: mpsc::UnboundedReceiver<UpdateEvent>,
    update_tx: mpsc::UnboundedSender<UpdateEvent>,
    pending_update: Option<UpdateCandidate>,
    send_control: Option<TransferControl>,
    receiver_control: Option<TransferControl>,
    pending_approvals: VecDeque<PendingApproval>,
    network_update_version: Option<String>,
    _release_server: Option<ReleaseServer>,
    installed_digest: Option<String>,
    network_update: Option<NetworkUpdate>,
    dismissed_updates: HashSet<String>,
    downloading_update: bool,
    internet_updater: updater::internet::InternetUpdater,
    internet_status: String,
}

impl RussApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(dark_visuals());

        let (config, mut status) = match AppConfig::load() {
            Ok(config) => (config, "Ready".to_owned()),
            Err(error) => {
                error!(%error, "could not load configuration; using defaults");
                (
                    AppConfig::default(),
                    format!("Configuration could not be loaded: {error}"),
                )
            }
        };
        let identity_path = database::app_directory().join("identity.json");
        let identity = match DeviceIdentity::load_or_create(&identity_path, &config.device_name) {
            Ok(identity) => identity,
            Err(error) => {
                error!(%error, "could not load device identity");
                status = format!("Device identity error: {error}");
                DeviceIdentity::new(&config.device_name)
                    .expect("RUSS requires a local TLS device identity")
            }
        };
        let hardware = HardwareSnapshot::detect();
        let engine = TransferEngine::new(hardware.clone(), config.optimizer.clone());
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Tokio runtime must be available"),
        );
        let (hash_tx, hash_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (discovery, discovery_rx) =
            match network::start_discovery(runtime.handle(), identity.device_id.clone()) {
                Ok((handle, receiver)) => (Some(handle), receiver),
                Err(error) => {
                    error!(%error, "LAN discovery is unavailable; manual addresses remain usable");
                    status = format!("LAN discovery unavailable: {error}");
                    let (_sender, receiver) = mpsc::unbounded_channel::<DiscoveryEvent>();
                    (None, receiver)
                }
            };
        let (update_tx, update_rx) = mpsc::unbounded_channel();
        let internet_updater = {
            let _guard = runtime.enter();
            updater::internet::InternetUpdater::start(
                config.internet_updates.clone(),
                database::updates_directory(),
                update_tx.clone(),
            )
        };
        let releases_directory = database::updates_directory().join("releases");
        let release_server = {
            let _guard = runtime.enter();
            distribution::start_server(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), distribution::UPDATE_PORT),
                &identity,
                releases_directory.clone(),
            )
            .map_err(|error| error!(%error, "LAN update server unavailable"))
            .ok()
        };
        if let (Some(discovery), Some(server)) = (&discovery, &release_server) {
            discovery.publish_updates(
                UpdateAnnouncement {
                    protocol: "russ-update/1".to_owned(),
                    device_id: identity.device_id.clone(),
                    device_name: identity.device_name.clone(),
                    certificate_fingerprint: identity
                        .certificate_fingerprint
                        .clone()
                        .unwrap_or_default(),
                    port: server.address.port(),
                    releases: Vec::new(),
                },
                releases_directory.clone(),
            );
        }
        if let Ok(executable) = updater::running_image_path() {
            let events = update_tx.clone();
            runtime.spawn_blocking(move || {
                if let Ok(digest) = updater::artifact_sha256(&executable) {
                    let _ = events.send(UpdateEvent::InstalledDigest(digest));
                }
                let own_target = updater::current_target();
                if !distribution::available_releases(&releases_directory)
                    .iter()
                    .any(|release| {
                        release.target == own_target
                            && (!is_newer_version(env!("CARGO_PKG_VERSION"), &release.version)
                                && (is_newer_version(&release.version, env!("CARGO_PKG_VERSION"))
                                    || release.built_unix_seconds
                                        >= env!("RUSS_BUILD_UNIX_SECONDS")
                                            .parse()
                                            .unwrap_or_default()))
                    })
                {
                    if let Err(error) = distribution::publish_release(
                        &releases_directory,
                        &executable,
                        env!("CARGO_PKG_VERSION"),
                        &own_target,
                        "Connection reliability and LAN update delivery",
                    ) {
                        error!(%error, "could not publish installed build");
                    }
                }
            });
        }
        let update_watcher = match updater::running_image_path() {
            Ok(current_executable) => match UpdateWatcher::start(
                database::updates_directory().join("manifest.json"),
                current_executable,
                update_tx.clone(),
            ) {
                Ok(watcher) => Some(watcher),
                Err(error) => {
                    error!(%error, "automatic updates are unavailable");
                    None
                }
            },
            Err(error) => {
                error!(%error, "could not resolve current executable for updates");
                None
            }
        };

        let receiver = gui::receiver::ReceiverState {
            output_directory: config.output_directory.clone(),
            port: "4433".to_owned(),
            selected_interface: config.selected_interface.clone(),
            ..Default::default()
        };

        Self {
            config,
            identity,
            screen: Screen::Dashboard,
            hardware,
            engine,
            sender: gui::sender::SenderState::default(),
            receiver,
            status,
            runtime,
            hash_tx,
            hash_rx,
            event_tx,
            event_rx,
            discovery,
            discovery_rx,
            _update_watcher: update_watcher,
            update_rx,
            update_tx,
            pending_update: None,
            send_control: None,
            receiver_control: None,
            pending_approvals: VecDeque::new(),
            network_update_version: None,
            _release_server: release_server,
            installed_digest: None,
            network_update: None,
            dismissed_updates: HashSet::new(),
            downloading_update: false,
            internet_updater,
            internet_status: "Starting update checks".to_owned(),
        }
    }

    fn start_send(&mut self) {
        if self.sender.running {
            return;
        }
        let target = match self.sender.target_address.trim().parse::<SocketAddr>() {
            Ok(target) => target,
            Err(error) => {
                self.status = format!("Invalid receiver address: {error}");
                return;
            }
        };
        let source = match self.sender.selected_path.clone() {
            Some(source) => source,
            None => {
                self.status = "Choose a file or folder first".to_owned();
                return;
            }
        };

        let control = TransferControl::default();
        self.send_control = Some(control.clone());
        self.sender.running = true;
        self.sender.paused = false;
        self.sender.bytes_transferred = 0;
        self.sender.total_bytes = 0;
        self.sender.speed_bytes_per_second = 0.0;
        self.sender.current_path = "preparing manifest".to_owned();
        self.sender.status = "Scanning selected files and folders".to_owned();
        self.status = "Starting secure TLS 1.3 transfer".to_owned();

        let expected_peer_fingerprint = if self.sender.server_fingerprint.trim().is_empty() {
            None
        } else {
            match crate::security::normalize_fingerprint(&self.sender.server_fingerprint) {
                Some(fingerprint) => Some(fingerprint),
                None => {
                    self.sender.running = false;
                    self.send_control = None;
                    self.status =
                        "Receiver fingerprint must be a 64-character SHA-256 digest".to_owned();
                    return;
                }
            }
        };
        let security = TransferSecurity {
            identity: self.identity.clone(),
            operating_system: self.hardware.operating_system.clone(),
            trusted_friends: self.config.friends.clone(),
            expected_peer_fingerprint,
        };

        let events = self.event_tx.clone();
        let engine = self.engine.clone();
        self.runtime.spawn(async move {
            if let Err(error) =
                network::send_path(target, source, security, engine, events.clone(), control).await
            {
                let _ = events.send(TransferEvent::Failed {
                    direction: TransferDirection::Sending,
                    transfer_id: "local".to_owned(),
                    error: format!("{error:#}"),
                });
            }
        });
    }

    fn start_receiver(&mut self) {
        if self.receiver.running {
            return;
        }
        let port = match self.receiver.port.trim().parse::<u16>() {
            Ok(port) if port != 0 => port,
            _ => {
                self.status = "Listening port must be a non-zero number".to_owned();
                return;
            }
        };
        let output_directory = match self.receiver.output_directory.clone() {
            Some(directory) => directory,
            None => {
                self.status = "Choose an output folder first".to_owned();
                return;
            }
        };

        let bind_ip = self
            .receiver
            .selected_interface
            .as_deref()
            .and_then(|selected| {
                self.hardware
                    .network
                    .interfaces
                    .iter()
                    .find(|interface| interface.name == selected)
                    .and_then(|interface| interface.ipv4_addresses.first())
                    .and_then(|address| address.parse::<IpAddr>().ok())
            })
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let bind_address = SocketAddr::new(bind_ip, port);
        let control = TransferControl::default();
        self.receiver_control = Some(control.clone());
        self.receiver.running = true;
        self.receiver.paused = false;
        self.receiver.listening_address = None;
        self.receiver.status_reset();
        self.status = format!("Starting TCP receiver on {bind_address}");

        let security = TransferSecurity {
            identity: self.identity.clone(),
            operating_system: self.hardware.operating_system.clone(),
            trusted_friends: self.config.friends.clone(),
            expected_peer_fingerprint: None,
        };

        let events = self.event_tx.clone();
        let engine = self.engine.clone();
        self.runtime.spawn(async move {
            if let Err(error) = network::run_receiver(
                bind_address,
                output_directory,
                security,
                engine,
                events.clone(),
                control,
            )
            .await
            {
                let _ = events.send(TransferEvent::ListenerFailed {
                    error: error.to_string(),
                });
            }
        });
    }

    fn handle_transfer_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                TransferEvent::Status { direction, message } => {
                    match direction {
                        TransferDirection::Sending => self.sender.status = message.clone(),
                        TransferDirection::Receiving => self.receiver.status = message.clone(),
                    }
                    self.status = message;
                }
                TransferEvent::Listening { address } => {
                    self.receiver.running = true;
                    let advertised = if address.ip().is_unspecified() {
                        self.hardware
                            .network
                            .interfaces
                            .iter()
                            .filter(|interface| interface.usable_by_default)
                            .find_map(|interface| {
                                interface
                                    .ipv4_addresses
                                    .first()
                                    .and_then(|ip| ip.parse::<IpAddr>().ok())
                                    .map(|ip| SocketAddr::new(ip, address.port()))
                            })
                            .unwrap_or(address)
                    } else {
                        address
                    };
                    self.receiver.listening_address = Some(advertised);
                    self.receiver.status = format!("Listening on {advertised}");
                    self.status = format!("Receiver listening on {advertised}");
                    if let Some(discovery) = &self.discovery {
                        discovery.advertise(DiscoveryAnnouncement::new(
                            self.identity.device_id.clone(),
                            self.identity.device_name.clone(),
                            address.port(),
                            self.hardware.operating_system.clone(),
                            self.identity
                                .certificate_fingerprint
                                .clone()
                                .unwrap_or_default(),
                            env!("CARGO_PKG_VERSION"),
                        ));
                    }
                }
                TransferEvent::ListenerFailed { error } => {
                    if let Some(discovery) = &self.discovery {
                        discovery.clear_advertisement();
                    }
                    self.receiver.running = false;
                    self.receiver_control = None;
                    self.receiver.status = format!("Receiver stopped: {error}");
                    self.status = self.receiver.status.clone();
                }
                TransferEvent::ApprovalRequested {
                    direction,
                    transfer_id,
                    device_id,
                    device_name,
                    operating_system,
                    certificate_fingerprint,
                    peer,
                    responder,
                } => {
                    // A listener retains its startup security snapshot. Consult
                    // current trust here so reconnects don't ask repeatedly.
                    if self.config.friends.iter().any(|friend| {
                        friend.trusted
                            && friend.device_id == device_id
                            && crate::security::normalize_fingerprint(
                                &friend.certificate_fingerprint,
                            ) == crate::security::normalize_fingerprint(&certificate_fingerprint)
                            && crate::security::normalize_fingerprint(&certificate_fingerprint)
                                .is_some()
                    }) {
                        let _ = responder.send(true);
                        continue;
                    }
                    self.pending_approvals.push_back(PendingApproval {
                        direction,
                        transfer_id,
                        device_id,
                        device_name,
                        operating_system,
                        certificate_fingerprint,
                        peer,
                        responder,
                    });
                    self.status = "A new device is waiting for explicit approval".to_owned();
                }
                TransferEvent::Started {
                    direction,
                    transfer_id,
                    file_count,
                    total_bytes,
                    peer,
                } => match direction {
                    TransferDirection::Sending => {
                        self.sender.transfer_id = Some(transfer_id);
                        self.sender.total_bytes = total_bytes;
                        self.sender.bytes_transferred = 0;
                        self.sender.current_path =
                            format!("sending {file_count} file(s) to {peer}");
                        self.sender.status = "Receiver accepted the manifest".to_owned();
                    }
                    TransferDirection::Receiving => {
                        self.receiver.transfer_id = Some(transfer_id);
                        self.receiver.total_bytes = total_bytes;
                        self.receiver.bytes_transferred = 0;
                        self.receiver.current_path =
                            format!("receiving {file_count} file(s) from {peer}");
                        self.receiver.status = "Manifest accepted; receiving".to_owned();
                    }
                },
                TransferEvent::Progress {
                    direction,
                    transfer_id,
                    current_path,
                    bytes_transferred,
                    total_bytes,
                    bytes_per_second,
                } => match direction {
                    TransferDirection::Sending
                        if self.sender.transfer_id.as_deref() == Some(transfer_id.as_str()) =>
                    {
                        self.sender.current_path = current_path;
                        self.sender.bytes_transferred = bytes_transferred;
                        self.sender.total_bytes = total_bytes;
                        self.sender.speed_bytes_per_second = bytes_per_second;
                    }
                    TransferDirection::Receiving
                        if self.receiver.transfer_id.as_deref() == Some(transfer_id.as_str()) =>
                    {
                        self.receiver.current_path = current_path;
                        self.receiver.bytes_transferred = bytes_transferred;
                        self.receiver.total_bytes = total_bytes;
                        self.receiver.speed_bytes_per_second = bytes_per_second;
                    }
                    _ => {}
                },
                TransferEvent::Completed {
                    direction,
                    transfer_id,
                    bytes_transferred,
                } => match direction {
                    TransferDirection::Sending => {
                        self.sender.running = false;
                        self.sender.paused = false;
                        self.sender.status = format!("Sent {bytes_transferred} bytes successfully");
                        self.status = self.sender.status.clone();
                        self.send_control = None;
                        self.record_history("send", transfer_id, bytes_transferred, true);
                    }
                    TransferDirection::Receiving => {
                        self.receiver.status = format!(
                            "Received {bytes_transferred} bytes successfully; still listening"
                        );
                        self.receiver.transfer_id = None;
                        self.status = self.receiver.status.clone();
                        self.record_history("receive", transfer_id, bytes_transferred, true);
                    }
                },
                TransferEvent::Failed {
                    direction,
                    transfer_id,
                    error,
                } => match direction {
                    TransferDirection::Sending => {
                        self.sender.running = false;
                        self.sender.paused = false;
                        self.sender.status = format!("Send failed: {error}");
                        self.status = self.sender.status.clone();
                        self.send_control = None;
                        self.record_history("send", transfer_id, 0, false);
                    }
                    TransferDirection::Receiving => {
                        self.receiver.status = format!("Incoming transfer failed: {error}");
                        if self.engine.active_receivers() == 0 {
                            self.receiver.transfer_id = None;
                        }
                        self.status = self.receiver.status.clone();
                    }
                },
            }
        }
    }

    fn handle_discovery_events(&mut self) {
        let mut changed = false;
        while let Ok(event) = self.discovery_rx.try_recv() {
            match event {
                DiscoveryEvent::Update {
                    announcement,
                    address,
                } => {
                    if self.downloading_update {
                        continue;
                    }
                    let Some(release) = announcement
                        .releases
                        .iter()
                        .find(|release| {
                            release.target == updater::current_target()
                                && !is_newer_version(env!("CARGO_PKG_VERSION"), &release.version)
                                && (is_newer_version(&release.version, env!("CARGO_PKG_VERSION"))
                                    || release.built_unix_seconds
                                        > env!("RUSS_BUILD_UNIX_SECONDS")
                                            .parse()
                                            .unwrap_or_default())
                                && self
                                    .installed_digest
                                    .as_ref()
                                    .is_some_and(|digest| digest != &release.sha256)
                                && !self.dismissed_updates.contains(&release.sha256)
                                && self.pending_update.as_ref().is_none_or(|candidate| {
                                    candidate.manifest.sha256 != release.sha256
                                })
                        })
                        .cloned()
                    else {
                        continue;
                    };
                    self.network_update = Some(NetworkUpdate {
                        announcement,
                        address,
                        release,
                    });
                }
                DiscoveryEvent::Peer {
                    announcement,
                    address,
                } => {
                    let Some(fingerprint) = crate::security::normalize_fingerprint(
                        &announcement.certificate_fingerprint,
                    ) else {
                        continue;
                    };
                    let peer_version = announcement.app_version.clone();
                    let peer_name_for_version = announcement.device_name.clone();
                    if let Some(friend) = self
                        .config
                        .friends
                        .iter_mut()
                        .find(|friend| friend.device_id == announcement.device_id)
                    {
                        let previous_address = friend.display_address();
                        if friend.trusted
                            && crate::security::normalize_fingerprint(
                                &friend.certificate_fingerprint,
                            )
                            .as_deref()
                                != Some(fingerprint.as_str())
                        {
                            self.status = format!(
                                "Ignoring a discovery announcement with a different fingerprint for {}",
                                announcement.device_name
                            );
                            continue;
                        }
                        if friend.device_name != announcement.device_name
                            || friend.operating_system != announcement.operating_system
                            || friend.last_known_ip.as_deref() != Some(&address.ip().to_string())
                            || friend.port != address.port()
                            || friend.certificate_fingerprint != fingerprint
                        {
                            friend.device_name = announcement.device_name.clone();
                            friend.operating_system = announcement.operating_system.clone();
                            friend.last_known_ip = Some(address.ip().to_string());
                            friend.port = address.port();
                            friend.certificate_fingerprint = fingerprint;
                            if !self.sender.running
                                && self.sender.target_address == previous_address
                                && crate::security::normalize_fingerprint(
                                    &self.sender.server_fingerprint,
                                ) == crate::security::normalize_fingerprint(
                                    &friend.certificate_fingerprint,
                                )
                            {
                                self.sender.target_address = friend.display_address();
                            }
                            changed = true;
                        }
                    } else {
                        self.config.friends.push(SavedFriend {
                            device_name: announcement.device_name,
                            device_id: announcement.device_id,
                            last_known_ip: Some(address.ip().to_string()),
                            port: address.port(),
                            operating_system: announcement.operating_system,
                            certificate_fingerprint: fingerprint,
                            last_connection_unix_seconds: None,
                            trusted: false,
                        });
                        changed = true;
                    }
                    if !peer_version.is_empty()
                        && is_newer_version(&peer_version, env!("CARGO_PKG_VERSION"))
                        && self.network_update_version.as_deref() != Some(&peer_version)
                    {
                        self.network_update_version = Some(peer_version.clone());
                        self.status = format!(
                            "Version {} is available on the network (from {})",
                            peer_version, peer_name_for_version
                        );
                    }
                }
                DiscoveryEvent::Failed { error } => {
                    error!(%error, "LAN discovery worker stopped");
                }
            }
        }
        if changed {
            self.save_config();
        }
    }

    fn handle_update_events(&mut self) {
        while let Ok(event) = self.update_rx.try_recv() {
            match event {
                UpdateEvent::InternetStatus(status) => self.internet_status = status,
                UpdateEvent::InstalledDigest(digest) => self.installed_digest = Some(digest),
                UpdateEvent::Available(candidate) => {
                    self.downloading_update = false;
                    let is_new = self
                        .pending_update
                        .as_ref()
                        .map(|current| current.manifest.sha256 != candidate.manifest.sha256)
                        .unwrap_or(true);
                    if is_new {
                        self.status =
                            format!("Update {} is ready to install", candidate.manifest.version);
                        self.pending_update = Some(candidate);
                    }
                }
                UpdateEvent::Failed(error) => {
                    self.downloading_update = false;
                    self.status = format!("Update: {error}");
                    error!(%error, "update watcher error");
                }
            }
        }
    }

    fn install_pending_update(&mut self) {
        if self.sender.running || self.engine.active_receivers() != 0 {
            self.status =
                "Finish or cancel active transfers before installing the update".to_owned();
            return;
        }
        let Some(candidate) = self.pending_update.clone() else {
            return;
        };
        let current_executable = match updater::installation_path() {
            Ok(path) => path,
            Err(error) => {
                self.status = format!("Could not resolve current executable: {error}");
                return;
            }
        };
        let restart_args = std::env::args().skip(1).collect::<Vec<_>>();
        match updater::launch_update(&candidate, current_executable, restart_args) {
            Ok(()) => {
                self.status = "Update staged; restarting RUSS…".to_owned();
                std::process::exit(0);
            }
            Err(error) => {
                self.status = format!("Update could not be installed: {error}");
            }
        }
    }

    fn show_update_dialog(&mut self, ctx: &egui::Context) {
        let Some(candidate) = self.pending_update.as_ref() else {
            return;
        };
        let mut install = false;
        let mut dismiss = false;
        egui::Window::new("RUSS update available")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!(
                    "Version {} for {} is ready.",
                    candidate.manifest.version, candidate.manifest.target
                ));
                ui.label(format!(
                    "Artifact: {} ({})",
                    candidate.artifact_path.display(),
                    crate::hardware::format_bytes(candidate.artifact_size)
                ));
                ui.monospace(format!("SHA-256: {}", candidate.manifest.sha256));
                if let Some(notes) = &candidate.manifest.release_notes {
                    ui.separator();
                    ui.label(notes);
                }
                ui.label("The artifact was verified before this prompt was shown.");
                if self.sender.running || self.engine.active_receivers() != 0 {
                    ui.label("Finish or cancel active transfers before restarting.");
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !self.sender.running && self.engine.active_receivers() == 0,
                            egui::Button::new("Install and restart"),
                        )
                        .clicked()
                    {
                        install = true;
                    }
                    if ui.button("Later").clicked() {
                        dismiss = true;
                    }
                });
            });
        if dismiss {
            if let Some(candidate) = &self.pending_update {
                self.dismissed_updates
                    .insert(candidate.manifest.sha256.clone());
            }
            self.pending_update = None;
        } else if install {
            self.install_pending_update();
        }
    }

    fn show_network_update_dialog(&mut self, ctx: &egui::Context) {
        if self.pending_update.is_none() && !self.downloading_update {
            if let Some(update) = &self.network_update {
                let mut download = false;
                let mut dismiss = false;
                egui::Window::new("RUSS update ready to download")
                    .collapsible(false).resizable(false).show(ctx, |ui| {
                        ui.label(format!("RUSS {} is available from {} at {}.",
                            update.release.version, update.announcement.device_name, update.address));
                        let trusted = self.config.friends.iter().any(|friend| friend.trusted
                            && friend.device_id == update.announcement.device_id
                            && crate::security::normalize_fingerprint(&friend.certificate_fingerprint)
                                == crate::security::normalize_fingerprint(&update.announcement.certificate_fingerprint));
                        if !trusted {
                            ui.label("Approve this update publisher after comparing its fingerprint independently:");
                            ui.monospace(&update.announcement.certificate_fingerprint);
                        }
                        ui.label("The download verifies the publisher identity and file integrity before installation.");
                        ui.horizontal(|ui| {
                            download = ui.button(if trusted { "Download update" } else { "Approve publisher and download" }).clicked();
                            dismiss = ui.button("Later").clicked();
                        });
                    });
                if download || dismiss {
                    let update = self.network_update.take().expect("displayed update");
                    self.dismissed_updates.insert(update.release.sha256.clone());
                    if download {
                        self.downloading_update = true;
                        self.status = "Downloading and verifying RUSS update…".to_owned();
                        let identity = self.identity.clone();
                        let events = self.update_tx.clone();
                        self.runtime.spawn(async move {
                            let result = async {
                                distribution::download_release(
                                    update.address,
                                    &update.announcement.certificate_fingerprint,
                                    &update.release,
                                    &identity,
                                    &database::updates_directory(),
                                    &updater::running_image_path()?,
                                )
                                .await
                            }
                            .await;
                            let event = match result {
                                Ok(candidate) => UpdateEvent::Available(candidate),
                                Err(error) => {
                                    UpdateEvent::Failed(format!("download failed: {error:#}"))
                                }
                            };
                            let _ = events.send(event);
                        });
                    }
                }
            }
        }
        if self.network_update.is_some() || self.pending_update.is_some() || self.downloading_update
        {
            return;
        }
        let Some(version) = self.network_update_version.as_ref() else {
            return;
        };
        let version = version.clone();
        let mut dismiss = false;
        egui::Window::new("Update available on the network")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!(
                    "A device on your network is running version {}.",
                    version
                ));
                ui.label(format!(
                    "You are running version {}.",
                    env!("CARGO_PKG_VERSION")
                ));
                ui.add_space(4.0);
                ui.label("Please update your application to the latest version.");
                ui.add_space(8.0);
                if ui.button("Dismiss").clicked() {
                    dismiss = true;
                }
            });
        if dismiss {
            self.network_update_version = None;
        }
    }

    fn record_history(
        &mut self,
        direction: &str,
        transfer_id: String,
        bytes: u64,
        succeeded: bool,
    ) {
        self.config
            .history
            .push(crate::storage::TransferHistoryEntry {
                transfer_id,
                direction: direction.to_owned(),
                peer_device_name: "LAN peer".to_owned(),
                bytes,
                sha256: None,
                completed_at_unix_seconds: current_unix_seconds(),
                succeeded,
            });
        if self.config.history.len() > 100 {
            let excess = self.config.history.len() - 100;
            self.config.history.drain(0..excess);
        }
        if let Err(error) = self.config.save() {
            error!(%error, "could not save transfer history");
        }
    }

    fn finish_approval(&mut self, approved: bool) {
        let Some(pending) = self.pending_approvals.pop_front() else {
            return;
        };

        if approved {
            let port = match pending.direction {
                TransferDirection::Sending => self
                    .sender
                    .target_address
                    .parse::<SocketAddr>()
                    .map(|address| address.port())
                    .unwrap_or(4433),
                TransferDirection::Receiving => self.receiver.port.parse().unwrap_or(4433),
            };
            let last_known_ip = pending
                .peer
                .parse::<SocketAddr>()
                .ok()
                .map(|address| address.ip().to_string());
            let friend = SavedFriend {
                device_name: pending.device_name.clone(),
                device_id: pending.device_id.clone(),
                last_known_ip,
                port,
                operating_system: pending.operating_system.clone(),
                certificate_fingerprint: pending.certificate_fingerprint.clone(),
                last_connection_unix_seconds: Some(current_unix_seconds()),
                trusted: true,
            };
            if let Some(existing) = self
                .config
                .friends
                .iter_mut()
                .find(|existing| existing.device_id == friend.device_id)
            {
                *existing = friend;
            } else {
                self.config.friends.push(friend);
            }
            self.save_config();
            self.status = format!("Trusted device '{}'", pending.device_name);
        } else {
            self.status = format!("Rejected device '{}'", pending.device_name);
        }
        let _ = pending.responder.send(approved);
    }

    fn show_approval_dialog(&mut self, ctx: &egui::Context) {
        let mut waiting = VecDeque::new();
        for pending in self.pending_approvals.drain(..) {
            if self.config.friends.iter().any(|friend| {
                friend.trusted
                    && friend.device_id == pending.device_id
                    && crate::security::normalize_fingerprint(&friend.certificate_fingerprint)
                        == crate::security::normalize_fingerprint(&pending.certificate_fingerprint)
                    && crate::security::normalize_fingerprint(&pending.certificate_fingerprint)
                        .is_some()
            }) {
                let _ = pending.responder.send(true);
            } else {
                waiting.push_back(pending);
            }
        }
        self.pending_approvals = waiting;
        self.pending_approvals
            .retain(|pending| !pending.responder.is_closed());
        let Some(pending) = self.pending_approvals.front() else {
            return;
        };
        let mut decision = None;
        egui::Window::new("Approve RUSS device")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(match pending.direction {
                    TransferDirection::Sending => "The receiver is not trusted yet.",
                    TransferDirection::Receiving => "An incoming sender is not trusted yet.",
                });
                ui.label(format!("Device: {}", pending.device_name));
                ui.label(format!("Operating system: {}", pending.operating_system));
                ui.label(format!("Address: {}", pending.peer));
                ui.label(format!("Transfer: {}", pending.transfer_id));
                ui.label("Verify this fingerprint independently before approving:");
                ui.monospace(&pending.certificate_fingerprint);
                ui.horizontal(|ui| {
                    if ui.button("Approve and trust").clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Reject").clicked() {
                        decision = Some(false);
                    }
                });
            });
        if let Some(decision) = decision {
            self.finish_approval(decision);
        }
    }

    fn pause_send(&mut self) {
        if let Some(control) = &self.send_control {
            control.pause();
            self.sender.paused = true;
            self.sender.status = "Send paused".to_owned();
        }
    }

    fn resume_send(&mut self) {
        if let Some(control) = &self.send_control {
            control.resume();
            self.sender.paused = false;
            self.sender.status = "Send resumed".to_owned();
        }
    }

    fn cancel_send(&mut self) {
        if let Some(control) = &self.send_control {
            control.cancel();
        }
        self.sender.running = false;
        self.sender.paused = false;
        self.sender.status = "Send cancelled".to_owned();
        self.status = self.sender.status.clone();
        self.send_control = None;
    }

    fn pause_receiver(&mut self) {
        if let Some(control) = &self.receiver_control {
            control.pause();
            self.receiver.paused = true;
            self.receiver.status = "Incoming transfers paused".to_owned();
        }
    }

    fn resume_receiver(&mut self) {
        if let Some(control) = &self.receiver_control {
            control.resume();
            self.receiver.paused = false;
            self.receiver.status = "Incoming transfers resumed".to_owned();
        }
    }

    fn stop_receiver(&mut self) {
        if let Some(control) = &self.receiver_control {
            control.cancel();
        }
        self.receiver.running = false;
        self.receiver.paused = false;
        self.receiver.status = "Receiver stopped".to_owned();
        self.status = self.receiver.status.clone();
        self.receiver_control = None;
        if let Some(discovery) = &self.discovery {
            discovery.clear_advertisement();
        }
    }

    fn refresh_hardware(&mut self) {
        self.hardware = HardwareSnapshot::detect();
        self.engine.replace_profile(self.hardware.clone());
        self.status = "Hardware and network profile refreshed".to_owned();
        info!(
            logical_cores = self.hardware.cpu.logical_cores,
            available_memory = self.hardware.memory.available_bytes,
            interfaces = self.hardware.network.interfaces.len(),
            "hardware profile refreshed"
        );
    }

    fn select_source(&mut self, path: PathBuf) {
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => match core::inspect_file(&path) {
                Ok(inspection) => self.start_hash(path, inspection),
                Err(error) => self.status = format!("Could not inspect file: {error}"),
            },
            Ok(metadata) if metadata.is_dir() => {
                self.sender.selected_path = Some(path.clone());
                self.sender.inspection = None;
                self.sender.hashing = false;
                self.sender.status =
                    "Folder selected; manifest scanning will run when transfers are enabled."
                        .to_owned();
                self.status = format!("Selected folder: {}", path.display());
            }
            Ok(_) => self.status = "Selected path is not a regular file or folder".to_owned(),
            Err(error) => self.status = format!("Could not inspect selected path: {error}"),
        }
    }

    fn start_hash(&mut self, path: PathBuf, inspection: FileInspection) {
        self.sender.selected_path = Some(path.clone());
        self.sender.inspection = Some(inspection);
        self.sender.hashing = true;
        self.sender.status = "Calculating SHA-256 with bounded I/O…".to_owned();
        self.status = "Hashing selected file in a Tokio worker".to_owned();

        let tx = self.hash_tx.clone();
        self.runtime.spawn(async move {
            let result = core::sha256_file(&path)
                .await
                .map_err(|error| error.to_string());
            let _ = tx.send(HashResult { path, result });
        });
    }

    fn drain_hash_results(&mut self) {
        while let Ok(result) = self.hash_rx.try_recv() {
            if self.sender.selected_path.as_ref() != Some(&result.path) {
                continue;
            }
            self.sender.hashing = false;
            match result.result {
                Ok(hash) => {
                    if let Some(inspection) = &mut self.sender.inspection {
                        inspection.sha256 = Some(hash);
                    }
                    self.sender.status = "SHA-256 complete".to_owned();
                    self.status = "File inspection complete".to_owned();
                }
                Err(error) => {
                    self.sender.status = format!("SHA-256 failed: {error}");
                    self.status = self.sender.status.clone();
                }
            }
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .find_map(|file| file.path.clone())
        });
        if self.screen == Screen::SendFiles {
            if let Some(path) = dropped {
                self.select_source(path);
            }
        }
    }

    fn save_config(&mut self) {
        self.config.output_directory = self.receiver.output_directory.clone();
        self.config.selected_interface = self.receiver.selected_interface.clone();
        self.config.optimizer = self.config.optimizer.normalized();
        if let Err(error) = self.config.save() {
            error!(%error, "could not save configuration");
            self.status = format!("Could not save configuration: {error}");
        }
    }

    fn top_navigation(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading("RUSS");
            ui.label("Rapid Universal Secure Sender");
            ui.separator();
            for screen in Screen::ALL {
                if ui
                    .selectable_label(self.screen == screen, screen.label())
                    .clicked()
                {
                    self.screen = screen;
                }
            }
        });
    }

    fn show_security(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Settings");
        ui.label(
            "RUSS uses explicit device identity and fingerprint approval before transfers begin.",
        );
        ui.add_space(10.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new("Active secure transport").strong());
            ui.label("TLS 1.3 with rustls, mutual certificate presentation, persistent device identity, and SHA-256 certificate fingerprint pinning.");
            ui.label("Unknown devices pause before manifest exchange until you approve the displayed fingerprint.");
            ui.label(format!("This device: {}", self.identity.device_name));
            ui.label(format!("Device ID: {}", self.identity.device_id));
            ui.monospace(format!(
                "Certificate fingerprint: {}",
                self.identity
                    .certificate_fingerprint
                    .as_deref()
                    .unwrap_or("unavailable")
            ));
        });
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new("Privacy boundary").strong());
            ui.label("Encryption protects file contents. A local network operator can still observe endpoints, connection timing, metadata, and traffic volume.");
            ui.label("No relay, telemetry, or external file storage is used by the local foundation.");
        });

        ui.add_space(10.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new("Internet updates").strong());
            ui.label(&self.internet_status);
            ui.label("Public HTTPS release feed:");
            ui.text_edit_singleline(&mut self.config.internet_updates.manifest_url);
            ui.label("Publisher public key (provided with the official release):");
            ui.text_edit_singleline(&mut self.config.internet_updates.public_key);
            ui.label("Checks run automatically at startup and every five minutes. Updates appear here before restarting the app.");
            if ui.button("Save and check now").clicked() {
                match self.config.internet_updates.validate() {
                    Ok(()) => {
                        self.save_config();
                        self.internet_updater.configure(self.config.internet_updates.clone());
                    }
                    Err(error) => self.internet_status = format!("Settings need attention: {error:#}"),
                }
            }
        });
        ui.add_space(10.0);
        let plan = self.engine.current_plan();
        if gui::settings::show(ui, &mut self.config.optimizer, &self.hardware, &plan) {
            self.config.optimizer = self.config.optimizer.normalized();
            self.engine.replace_config(self.config.optimizer.clone());
            self.save_config();
        }
    }
}

impl eframe::App for RussApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_hash_results();
        self.handle_discovery_events();
        self.handle_update_events();
        self.handle_transfer_events();
        self.handle_dropped_files(ctx);

        egui::TopBottomPanel::top("top-navigation").show(ctx, |ui| self.top_navigation(ui));
        egui::TopBottomPanel::bottom("status-bar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Status").strong());
                ui.label(&self.status);
                ui.separator();
                let plan = self.engine.current_plan();
                ui.label(format!(
                    "{} buffer · {} in flight",
                    crate::hardware::format_bytes(plan.buffer_size_bytes as u64),
                    crate::hardware::format_bytes(plan.max_in_flight_bytes as u64)
                ));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.screen {
            Screen::Dashboard => {
                let plan = self.engine.current_plan();
                if gui::dashboard::show(ui, &self.hardware, &plan) {
                    self.refresh_hardware();
                }
            }
            Screen::SendFiles => {
                if let Some(action) = gui::sender::show(ui, &mut self.sender) {
                    match action {
                        gui::sender::Action::PathSelected(path) => self.select_source(path),
                        gui::sender::Action::Start => self.start_send(),
                        gui::sender::Action::Pause => self.pause_send(),
                        gui::sender::Action::Resume => self.resume_send(),
                        gui::sender::Action::Cancel => self.cancel_send(),
                    }
                }
            }
            Screen::ReceiveFiles => {
                let previous_interface = self.receiver.selected_interface.clone();
                if let Some(action) = gui::receiver::show(ui, &mut self.receiver, &self.hardware) {
                    match action {
                        gui::receiver::Action::OutputDirectorySelected(path) => {
                            self.receiver.output_directory = Some(path.clone());
                            self.config.output_directory = Some(path);
                            self.save_config();
                        }
                        gui::receiver::Action::Start => self.start_receiver(),
                        gui::receiver::Action::Pause => self.pause_receiver(),
                        gui::receiver::Action::Resume => self.resume_receiver(),
                        gui::receiver::Action::Stop => self.stop_receiver(),
                    }
                } else if self.receiver.selected_interface != previous_interface {
                    self.save_config();
                }
            }
            Screen::SavedFriends => {
                if let Some(action) = gui::friends::show(ui, &mut self.config.friends) {
                    match action {
                        gui::friends::Action::Changed => self.save_config(),
                        gui::friends::Action::Use {
                            address,
                            fingerprint,
                        } => {
                            self.sender.target_address = address;
                            self.sender.server_fingerprint = fingerprint;
                            self.screen = Screen::SendFiles;
                            self.status = "Saved friend selected for sending".to_owned();
                        }
                    }
                }
            }
            Screen::ActiveTransfers => {
                let plan = self.engine.current_plan();
                gui::active_transfers::show(ui, &self.sender, &self.receiver, &plan);
            }
            Screen::History => gui::history::show(ui, &self.config.history),
            Screen::Security => self.show_security(ui),
        });

        self.show_approval_dialog(ctx);
        self.show_update_dialog(ctx);
        self.show_network_update_dialog(ctx);

        ctx.request_repaint_after(std::time::Duration::from_millis(250));
    }
}

fn dark_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(egui::Color32::from_rgb(228, 232, 240));
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(28, 31, 39);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(35, 40, 50);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(48, 56, 70);
    visuals.selection.bg_fill = egui::Color32::from_rgb(60, 108, 170);
    visuals
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn is_newer_version(remote: &str, local: &str) -> bool {
    matches!((semver::Version::parse(remote), semver::Version::parse(local)), (Ok(remote), Ok(local)) if remote > local)
}

impl Drop for RussApp {
    fn drop(&mut self) {
        if let Some(discovery) = &self.discovery {
            discovery.shutdown();
        }
    }
}
