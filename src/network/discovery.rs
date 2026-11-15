use crate::updater::distribution::{available_releases, UpdateAnnouncement};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::{
    net::UdpSocket,
    runtime::Handle,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time::{self, Duration, MissedTickBehavior},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub const DISCOVERY_PORT: u16 = 45_889;
const ANNOUNCEMENT_INTERVAL: Duration = Duration::from_secs(3);
const MAX_ANNOUNCEMENT_BYTES: usize = 8 * 1024;

/// LAN discovery payload.  It contains enough information to update a saved
/// friend's address, but never carries trust by itself; a fingerprint still
/// requires explicit approval during the secure handshake.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryAnnouncement {
    pub protocol: String,
    pub device_id: String,
    pub device_name: String,
    pub port: u16,
    pub operating_system: String,
    pub certificate_fingerprint: String,
    #[serde(default)]
    pub app_version: String,
}

impl DiscoveryAnnouncement {
    pub fn new(
        device_id: impl Into<String>,
        device_name: impl Into<String>,
        port: u16,
        operating_system: impl Into<String>,
        certificate_fingerprint: impl Into<String>,
        app_version: impl Into<String>,
    ) -> Self {
        Self {
            protocol: "russ/1".to_owned(),
            device_id: device_id.into(),
            device_name: device_name.into(),
            port,
            operating_system: operating_system.into(),
            certificate_fingerprint: certificate_fingerprint.into(),
            app_version: app_version.into(),
        }
    }
}

#[derive(Debug)]
pub enum DiscoveryEvent {
    Update {
        announcement: UpdateAnnouncement,
        address: SocketAddr,
    },
    Peer {
        announcement: DiscoveryAnnouncement,
        address: SocketAddr,
    },
    Failed {
        error: String,
    },
}

#[derive(Clone)]
pub struct DiscoveryHandle {
    commands: UnboundedSender<DiscoveryCommand>,
}

enum DiscoveryCommand {
    PublishUpdates(UpdateAnnouncement, PathBuf),
    Advertise(Option<DiscoveryAnnouncement>),
    Shutdown,
}

impl DiscoveryHandle {
    pub fn publish_updates(&self, announcement: UpdateAnnouncement, releases_directory: PathBuf) {
        let _ = self.commands.send(DiscoveryCommand::PublishUpdates(
            announcement,
            releases_directory,
        ));
    }
    pub fn advertise(&self, announcement: DiscoveryAnnouncement) {
        let _ = self
            .commands
            .send(DiscoveryCommand::Advertise(Some(announcement)));
    }

    pub fn clear_advertisement(&self) {
        let _ = self.commands.send(DiscoveryCommand::Advertise(None));
    }

    pub fn shutdown(&self) {
        let _ = self.commands.send(DiscoveryCommand::Shutdown);
    }
}

pub fn start_discovery(
    runtime: &Handle,
    local_device_id: impl Into<String>,
) -> std::io::Result<(DiscoveryHandle, UnboundedReceiver<DiscoveryEvent>)> {
    let socket = bind_discovery_socket()?;
    let (commands, command_rx) = mpsc::unbounded_channel();
    let (events, event_rx) = mpsc::unbounded_channel();
    let local_device_id = local_device_id.into();
    runtime.spawn(run_discovery(socket, local_device_id, command_rx, events));
    Ok((DiscoveryHandle { commands }, event_rx))
}

fn bind_discovery_socket() -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        DISCOVERY_PORT,
    )))?;
    Ok(socket.into())
}

async fn run_discovery(
    socket: std::net::UdpSocket,
    local_device_id: String,
    mut command_rx: UnboundedReceiver<DiscoveryCommand>,
    events: UnboundedSender<DiscoveryEvent>,
) {
    let socket = match UdpSocket::from_std(socket) {
        Ok(socket) => socket,
        Err(error) => {
            let _ = events.send(DiscoveryEvent::Failed {
                error: error.to_string(),
            });
            return;
        }
    };
    let mut broadcasts = vec![SocketAddr::new(
        IpAddr::V4(Ipv4Addr::BROADCAST),
        DISCOVERY_PORT,
    )];
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            if let if_addrs::IfAddr::V4(address) = interface.addr {
                if !address.ip.is_loopback() {
                    if let Some(broadcast) = address.broadcast {
                        broadcasts.push(SocketAddr::new(IpAddr::V4(broadcast), DISCOVERY_PORT));
                    }
                }
            }
        }
    }
    broadcasts.sort();
    broadcasts.dedup();
    let mut advertisement = None;
    let mut update_publisher: Option<(UpdateAnnouncement, PathBuf)> = None;
    let mut ticker = time::interval(ANNOUNCEMENT_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut buffer = [0_u8; MAX_ANNOUNCEMENT_BYTES];

    loop {
        tokio::select! {
            command = command_rx.recv() => match command {
                Some(DiscoveryCommand::PublishUpdates(notice, directory)) => {
                    update_publisher = Some((notice, directory));
                    ticker.reset_immediately();
                }
                Some(DiscoveryCommand::Advertise(next)) => {
                    advertisement = next;
                    if let Some(announcement) = advertisement.as_ref() {
                        for broadcast in &broadcasts {
                            if let Err(error) = send_announcement(&socket, *broadcast, announcement).await {
                                tracing::debug!(%broadcast, %error, "discovery broadcast unavailable");
                            }
                        }
                    }
                }
                Some(DiscoveryCommand::Shutdown) | None => return,
            },
            result = socket.recv_from(&mut buffer) => match result {
                Ok((length, source)) => {
                    if let Ok(announcement) = serde_json::from_slice::<DiscoveryAnnouncement>(&buffer[..length]) {
                        if announcement.protocol == "russ/1"
                            && announcement.device_id != local_device_id
                            && announcement.port != 0
                            && is_valid_fingerprint(&announcement.certificate_fingerprint)
                        {
                            let address = SocketAddr::new(source.ip(), announcement.port);
                            let _ = events.send(DiscoveryEvent::Peer { announcement, address });
                        }
                    } else if let Ok(announcement) = serde_json::from_slice::<UpdateAnnouncement>(&buffer[..length]) {
                        if announcement.valid() && announcement.device_id != local_device_id {
                            let address = SocketAddr::new(source.ip(), announcement.port);
                            let _ = events.send(DiscoveryEvent::Update { announcement, address });
                        }
                    }
                }
                Err(error) => {
                    let _ = events.send(DiscoveryEvent::Failed { error: error.to_string() });
                    return;
                }
            },
            _ = ticker.tick() => {
                if let Some(announcement) = advertisement.as_ref() {
                    for broadcast in &broadcasts {
                        if let Err(error) = send_announcement(&socket, *broadcast, announcement).await {
                            tracing::debug!(%broadcast, %error, "discovery broadcast unavailable");
                        }
                    }
                }
                if let Some((notice, directory)) = &mut update_publisher {
                    notice.releases = available_releases(directory);
                    if !notice.releases.is_empty() {
                        for broadcast in &broadcasts {
                            let _ = send_announcement(&socket, *broadcast, notice).await;
                        }
                    }
                }
            }
        }
    }
}

async fn send_announcement<T: Serialize>(
    socket: &UdpSocket,
    broadcast: SocketAddr,
    announcement: &T,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec(announcement)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if payload.len() > MAX_ANNOUNCEMENT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "discovery announcement is too large",
        ));
    }
    socket.send_to(&payload, broadcast).await.map(|_| ())
}

fn is_valid_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
