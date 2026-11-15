use super::{
    connection::bind_tcp_listener,
    protocol::{
        read_message, write_message, WireManifestEntry, WireMessage, WireResumeEntry,
        MANIFEST_BATCH_SIZE, PROTOCOL_VERSION,
    },
};
use crate::core::{
    integrity::sha256_file,
    receiver::safe_destination,
    recovery::{load_checkpoint, remove_checkpoint, save_checkpoint, ResumeCheckpoint},
    sender::SendRequest,
    streaming::{BufferPool, TransferControl},
    ThroughputSample, TransferEngine, TransferManifest,
};
use crate::security::{self, DeviceIdentity};
use crate::storage::{database, SavedFriend};
use anyhow::{anyhow, Context, Result};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    net::{TcpListener, TcpStream},
    sync::{mpsc::UnboundedSender, oneshot, Semaphore},
    time,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

const MAX_MANIFEST_ENTRIES: u64 = 1_000_000;
const CHECKPOINT_INTERVAL_BYTES: u64 = 16 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(3);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECT_ATTEMPTS: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    Sending,
    Receiving,
}

pub enum TransferEvent {
    Status {
        direction: TransferDirection,
        message: String,
    },
    Listening {
        address: SocketAddr,
    },
    ListenerFailed {
        error: String,
    },
    ApprovalRequested {
        direction: TransferDirection,
        transfer_id: String,
        device_id: String,
        device_name: String,
        operating_system: String,
        certificate_fingerprint: String,
        peer: String,
        responder: oneshot::Sender<bool>,
    },
    Started {
        direction: TransferDirection,
        transfer_id: String,
        file_count: u64,
        total_bytes: u64,
        peer: String,
    },
    Progress {
        direction: TransferDirection,
        transfer_id: String,
        current_path: String,
        bytes_transferred: u64,
        total_bytes: u64,
        bytes_per_second: f64,
    },
    Completed {
        direction: TransferDirection,
        transfer_id: String,
        bytes_transferred: u64,
    },
    Failed {
        direction: TransferDirection,
        transfer_id: String,
        error: String,
    },
}

#[derive(Clone)]
pub struct TransferSecurity {
    pub identity: DeviceIdentity,
    pub operating_system: String,
    pub trusted_friends: Vec<SavedFriend>,
    pub expected_peer_fingerprint: Option<String>,
}

struct SendContext {
    request: SendRequest,
    transfer_id: String,
    peer: String,
    pool: BufferPool,
    events: UnboundedSender<TransferEvent>,
    control: TransferControl,
    engine: TransferEngine,
}

struct ReceiveContext {
    peer: SocketAddr,
    client_certificate_fingerprint: String,
    output_directory: PathBuf,
    security: TransferSecurity,
    engine: TransferEngine,
    events: UnboundedSender<TransferEvent>,
    control: TransferControl,
    transfer_slots: std::sync::Arc<Semaphore>,
}

struct ApprovalRequest<'a> {
    direction: TransferDirection,
    transfer_id: &'a str,
    device_id: &'a str,
    device_name: &'a str,
    operating_system: &'a str,
    certificate_fingerprint: &'a str,
    peer: &'a str,
}

struct ContentProgress<'a> {
    pool: &'a BufferPool,
    control: &'a TransferControl,
    events: &'a UnboundedSender<TransferEvent>,
    direction: TransferDirection,
    transfer_id: &'a str,
    relative_path: &'a str,
    bytes_before_file: u64,
    total_bytes: u64,
    started: Instant,
}

struct CheckpointContext<'a> {
    root: &'a Path,
    transfer_id: &'a str,
    relative_path: &'a str,
}

struct StreamMetrics {
    elapsed: std::time::Duration,
    read_wait: std::time::Duration,
    write_wait: std::time::Duration,
}

impl StreamMetrics {
    fn sample(&self, bytes: u64, sending: bool) -> ThroughputSample {
        let elapsed = self.elapsed.as_secs_f64().max(f64::EPSILON);
        let read_ratio = (self.read_wait.as_secs_f64() / elapsed).clamp(0.0, 1.0) as f32;
        let write_ratio = (self.write_wait.as_secs_f64() / elapsed).clamp(0.0, 1.0) as f32;
        ThroughputSample {
            elapsed: self.elapsed,
            bytes,
            backpressure_ratio: if sending { write_ratio } else { read_ratio },
            io_wait_ratio: if sending { read_ratio } else { write_ratio },
        }
    }
}

fn configure_tcp_keepalive(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true).context("enable TCP_NODELAY")?;
    let sock_ref = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    // Keepalive is an optimization. Unsupported OS options must not abort an
    // otherwise usable connection.
    if let Err(error) = sock_ref.set_tcp_keepalive(&keepalive) {
        debug!(%error, "TCP keepalive is unavailable");
    }
    Ok(())
}

fn status(events: &UnboundedSender<TransferEvent>, message: impl Into<String>) {
    let _ = events.send(TransferEvent::Status {
        direction: TransferDirection::Sending,
        message: message.into(),
    });
}

async fn setup_step<T>(
    duration: Duration,
    label: &str,
    future: impl std::future::Future<Output = std::io::Result<T>>,
) -> Result<T> {
    time::timeout(duration, future)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, label.to_owned()))?
        .with_context(|| label.to_owned())
}

async fn connect_peer(
    target: SocketAddr,
    security: &TransferSecurity,
    events: &UnboundedSender<TransferEvent>,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, WireMessage)> {
    let config = security::tls::client_config(
        &security.identity,
        security.expected_peer_fingerprint.as_deref(),
    )?;
    let connector = TlsConnector::from(std::sync::Arc::new(config));
    for attempt in 1..=MAX_CONNECT_ATTEMPTS {
        status(
            events,
            format!("Connecting to {target} (attempt {attempt}/{MAX_CONNECT_ATTEMPTS})"),
        );
        let result = async {
            let stream = setup_step(
                CONNECT_TIMEOUT,
                "TCP connection",
                TcpStream::connect(target),
            )
            .await?;
            configure_tcp_keepalive(&stream)?;
            status(events, "Securing connection with TLS 1.3");
            let server_name = rustls::pki_types::ServerName::try_from("russ".to_owned())?;
            let mut stream = setup_step(
                TLS_HANDSHAKE_TIMEOUT,
                "TLS handshake",
                connector.connect(server_name, stream),
            )
            .await?;
            status(events, "Checking receiver identity");
            let hello = setup_step(
                IDENTITY_TIMEOUT,
                "receiver identity",
                read_message(&mut stream),
            )
            .await?;
            Ok::<_, anyhow::Error>((stream, hello))
        }
        .await;
        match result {
            Ok(connected) => return Ok(connected),
            Err(error) => {
                let transient = error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::BrokenPipe
                    )
                });
                if !transient || attempt == MAX_CONNECT_ATTEMPTS {
                    return Err(error).with_context(|| {
                        format!("connect to {target} after {attempt} attempt(s)")
                    });
                }
                warn!(%target, attempt, error = %format!("{error:#}"), "connection setup interrupted; retrying");
                status(events, format!("Connection interrupted; retrying ({attempt}/{MAX_CONNECT_ATTEMPTS}): {error:#}"));
                time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
            }
        }
    }
    unreachable!("the connection attempt loop always returns")
}

pub async fn send_path(
    target: SocketAddr,
    source: PathBuf,
    security: TransferSecurity,
    engine: TransferEngine,
    events: UnboundedSender<TransferEvent>,
    control: TransferControl,
) -> Result<()> {
    tokio::select! {
        biased;
        _ = control.wait_until_cancelled() => Err(anyhow!("send cancelled")),
        result = send_path_inner(target, source, security, engine, events, control.clone()) => result,
    }
}

async fn send_path_inner(
    target: SocketAddr,
    source: PathBuf,
    security: TransferSecurity,
    engine: TransferEngine,
    events: UnboundedSender<TransferEvent>,
    control: TransferControl,
) -> Result<()> {
    status(&events, "Scanning selected files and folders");
    let scan_source = source.clone();
    let request = tokio::task::spawn_blocking(move || SendRequest::for_path(scan_source))
        .await
        .context("source scanner stopped")?
        .with_context(|| format!("prepare source {}", source.display()))?;
    let (mut stream, hello) = time::timeout(SETUP_TIMEOUT, connect_peer(target, &security, &events))
        .await.map_err(|_| anyhow!("connection setup to {target} exceeded 15 seconds; check receiver, address and firewall"))??;
    let server_certificate_fingerprint =
        peer_certificate_fingerprint(stream.get_ref().1.peer_certificates())?;
    let server = match hello {
        super::protocol::WireMessage::ServerHello {
            protocol_version,
            device_id,
            device_name,
            operating_system,
            certificate_fingerprint,
        } if protocol_version == PROTOCOL_VERSION
            && certificate_fingerprint == server_certificate_fingerprint =>
        {
            (
                device_id,
                device_name,
                operating_system,
                certificate_fingerprint,
            )
        }
        other => return Err(anyhow!("invalid receiver identity: {other:?}")),
    };
    let transfer_id = transfer_session_id(
        &source,
        &request.manifest,
        &security.identity,
        &server.0,
        &server.3,
    )?;
    // Exchange identities before either human approval. Both computers can
    // display their approval dialogs immediately, without waiting on each other.
    setup_step(
        IDENTITY_TIMEOUT,
        "send sender identity",
        write_message(
            &mut stream,
            &WireMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                device_id: security.identity.device_id.clone(),
                device_name: security.identity.device_name.clone(),
                operating_system: security.operating_system.clone(),
                certificate_fingerprint: identity_fingerprint(&security.identity)?,
                transfer_id: transfer_id.clone(),
            },
        ),
    )
    .await?;
    if !is_trusted(&security.trusted_friends, &server.0, &server.3) {
        status(&events, "Waiting for local device approval");
        request_approval(
            &events,
            ApprovalRequest {
                direction: TransferDirection::Sending,
                transfer_id: &transfer_id,
                device_id: &server.0,
                device_name: &server.1,
                operating_system: &server.2,
                certificate_fingerprint: &server.3,
                peer: &target.to_string(),
            },
        )
        .await?;
    }
    let pool = engine
        .buffer_pool()
        .context("create transfer buffer pool")?;

    send_request(
        &mut stream,
        SendContext {
            request,
            transfer_id,
            peer: target.to_string(),
            pool,
            events,
            control,
            engine,
        },
    )
    .await
}

async fn send_request<S>(stream: &mut S, context: SendContext) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let SendContext {
        request,
        transfer_id,
        peer,
        pool,
        events,
        control,
        engine,
    } = context;
    status(
        &events,
        "Sending manifest; waiting for receiver approval and preparation",
    );
    let file_count = request
        .manifest
        .entries
        .iter()
        .filter(|entry| !entry.is_directory)
        .count() as u64;
    write_message(
        stream,
        &WireMessage::OfferStart {
            transfer_id: transfer_id.clone(),
            file_count,
            total_bytes: request.manifest.total_bytes,
        },
    )
    .await
    .context("send transfer offer")?;

    for batch in request.manifest.entries.chunks(MANIFEST_BATCH_SIZE) {
        let entries = batch
            .iter()
            .map(WireManifestEntry::from_manifest_entry)
            .collect::<std::io::Result<Vec<_>>>()
            .context("encode manifest batch")?;
        write_message(
            stream,
            &WireMessage::ManifestBatch {
                transfer_id: transfer_id.clone(),
                entries,
            },
        )
        .await
        .context("send manifest batch")?;
    }
    write_message(
        stream,
        &WireMessage::OfferEnd {
            transfer_id: transfer_id.clone(),
        },
    )
    .await
    .context("finish transfer offer")?;

    let resume_offsets = match read_message(stream)
        .await
        .context("read receiver decision")?
    {
        WireMessage::Accept {
            transfer_id: accepted,
            resume,
        } if accepted == transfer_id => build_resume_offsets(&request.manifest, resume)?,
        WireMessage::Reject { reason, .. } => {
            return Err(anyhow!("receiver rejected transfer: {reason}"))
        }
        other => return Err(anyhow!("unexpected receiver decision: {other:?}")),
    };

    let started = Instant::now();
    let mut bytes_transferred = 0_u64;
    let _ = events.send(TransferEvent::Started {
        direction: TransferDirection::Sending,
        transfer_id: transfer_id.clone(),
        file_count,
        total_bytes: request.manifest.total_bytes,
        peer,
    });

    for entry in &request.manifest.entries {
        if entry.is_directory {
            continue;
        }
        control.wait_if_paused().await.context("wait before file")?;
        let relative_path = path_to_wire(&entry.relative_path)?;
        let offset_bytes = resume_offsets
            .get(&relative_path)
            .copied()
            .unwrap_or_default();
        let source_path = request.source_root().join(&entry.relative_path);
        let metadata = fs::metadata(&source_path)
            .await
            .with_context(|| format!("stat source {}", source_path.display()))?;
        if !metadata.is_file() || metadata.len() != entry.size_bytes {
            return Err(anyhow!(
                "source changed after manifest: {}",
                source_path.display()
            ));
        }

        write_message(
            stream,
            &WireMessage::FileStart {
                transfer_id: transfer_id.clone(),
                relative_path: relative_path.clone(),
                size_bytes: entry.size_bytes,
                offset_bytes,
            },
        )
        .await
        .context("send file header")?;

        let progress = ContentProgress {
            pool: &pool,
            control: &control,
            events: &events,
            direction: TransferDirection::Sending,
            transfer_id: &transfer_id,
            relative_path: &relative_path,
            bytes_before_file: bytes_transferred.saturating_add(offset_bytes),
            total_bytes: request.manifest.total_bytes,
            started,
        };
        let (sent, digest, metrics) = send_file_contents(
            stream,
            &source_path,
            entry.size_bytes,
            offset_bytes,
            &progress,
        )
        .await?;
        engine.observe(metrics.sample(sent, true));
        bytes_transferred = bytes_transferred
            .saturating_add(offset_bytes)
            .saturating_add(sent);

        write_message(
            stream,
            &WireMessage::FileComplete {
                transfer_id: transfer_id.clone(),
                relative_path: relative_path.clone(),
                sha256: digest,
            },
        )
        .await
        .context("send file digest")?;

        match read_message(stream)
            .await
            .context("read file acknowledgement")?
        {
            WireMessage::FileAck {
                transfer_id: acknowledged,
                relative_path: acknowledged_path,
            } if acknowledged == transfer_id && acknowledged_path == relative_path => {}
            other => return Err(anyhow!("unexpected file acknowledgement: {other:?}")),
        }
    }

    write_message(
        stream,
        &WireMessage::TransferComplete {
            transfer_id: transfer_id.clone(),
            total_bytes: bytes_transferred,
        },
    )
    .await
    .context("send transfer completion")?;
    match read_message(stream)
        .await
        .context("read transfer acknowledgement")?
    {
        WireMessage::TransferAck {
            transfer_id: acknowledged,
        } if acknowledged == transfer_id => {}
        other => return Err(anyhow!("unexpected transfer acknowledgement: {other:?}")),
    }

    let _ = events.send(TransferEvent::Completed {
        direction: TransferDirection::Sending,
        transfer_id,
        bytes_transferred,
    });
    Ok(())
}

pub async fn run_receiver(
    bind_address: SocketAddr,
    output_directory: PathBuf,
    security: TransferSecurity,
    engine: TransferEngine,
    events: UnboundedSender<TransferEvent>,
    control: TransferControl,
) -> Result<()> {
    fs::create_dir_all(&output_directory)
        .await
        .with_context(|| format!("create output directory {}", output_directory.display()))?;
    let listener = bind_tcp_listener(bind_address).context("bind TCP receiver")?;
    let tls_config = security::tls::server_config(&security.identity)
        .context("build TLS server configuration")?;
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));
    let address = listener.local_addr().context("read receiver address")?;
    let _ = events.send(TransferEvent::Listening { address });
    info!(%address, "RUSS TLS 1.3 receiver listening");

    accept_connections(
        listener,
        output_directory,
        security,
        acceptor,
        engine,
        events,
        control,
    )
    .await
}

async fn accept_connections(
    listener: TcpListener,
    output_directory: PathBuf,
    security: TransferSecurity,
    acceptor: TlsAcceptor,
    engine: TransferEngine,
    events: UnboundedSender<TransferEvent>,
    control: TransferControl,
) -> Result<()> {
    // Pending TLS/approval sessions must not consume the disk concurrency budget.
    // Never wait for a permit in the accept loop: a stalled peer otherwise
    // prevents all later clients from even beginning their TLS handshake.
    let connection_slots = std::sync::Arc::new(Semaphore::new(32));
    let transfer_slots = std::sync::Arc::new(Semaphore::new(
        engine.current_plan().concurrent_file_limit.max(1),
    ));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept TCP connection")?;
                let permit = match connection_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%peer, "receiver session limit reached");
                        continue;
                    }
                };
                let output_directory = output_directory.clone();
                let security = security.clone();
                let acceptor = acceptor.clone();
                let engine = engine.clone();
                let events = events.clone();
                let control = control.clone();
                let transfer_slots = transfer_slots.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let cancellation = control.clone();
                    let result = async {
                        configure_tcp_keepalive(&stream)?;
                        let mut stream = time::timeout(
                            TLS_HANDSHAKE_TIMEOUT,
                            acceptor.accept(stream),
                        )
                        .await
                        .map_err(|_| anyhow!("incoming TLS handshake timed out"))?
                        .context("complete TLS 1.3 handshake")?;
                        let client_certificate_fingerprint = peer_certificate_fingerprint(
                            stream.get_ref().1.peer_certificates(),
                        )?;
                        receive_connection(
                            &mut stream,
                            ReceiveContext {
                                peer,
                                client_certificate_fingerprint,
                                output_directory,
                                security,
                                engine,
                                events: events.clone(),
                                control,
                                transfer_slots,
                            },
                        )
                        .await
                    }
                    ;
                    let result = tokio::select! {
                        biased;
                        _ = cancellation.wait_until_cancelled() => return,
                        result = result => result,
                    };
                    if let Err(error) = result {
                        warn!(%peer, %error, "TCP transfer failed");
                        let _ = events.send(TransferEvent::Failed {
                            direction: TransferDirection::Receiving,
                            transfer_id: "unknown".to_owned(),
                            error: format!("{peer}: {error:#}"),
                        });
                    }
                });
            }
            _ = control.wait_until_cancelled() => {
                debug!("TCP receiver stopped by local control");
                return Ok(());
            }
        }
    }
}

async fn receive_connection<S>(stream: &mut S, context: ReceiveContext) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let ReceiveContext {
        peer,
        client_certificate_fingerprint,
        output_directory,
        security,
        engine,
        events,
        control,
        transfer_slots,
    } = context;
    write_message(
        stream,
        &WireMessage::ServerHello {
            protocol_version: PROTOCOL_VERSION,
            device_id: security.identity.device_id.clone(),
            device_name: security.identity.device_name.clone(),
            operating_system: security.operating_system.clone(),
            certificate_fingerprint: identity_fingerprint(&security.identity)?,
        },
    )
    .await
    .context("send receiver identity")?;

    let (transfer_id, device_id, device_name, operating_system) =
        match setup_step(APPROVAL_TIMEOUT, "read sender hello", read_message(stream)).await? {
            WireMessage::Hello {
                protocol_version,
                device_id,
                device_name,
                operating_system,
                certificate_fingerprint,
                transfer_id,
            } if protocol_version == PROTOCOL_VERSION
                && certificate_fingerprint == client_certificate_fingerprint =>
            {
                (transfer_id, device_id, device_name, operating_system)
            }
            other => return Err(anyhow!("invalid sender hello: {other:?}")),
        };
    if !is_trusted(
        &security.trusted_friends,
        &device_id,
        &client_certificate_fingerprint,
    ) {
        request_approval(
            &events,
            ApprovalRequest {
                direction: TransferDirection::Receiving,
                transfer_id: &transfer_id,
                device_id: &device_id,
                device_name: &device_name,
                operating_system: &operating_system,
                certificate_fingerprint: &client_certificate_fingerprint,
                peer: &peer.to_string(),
            },
        )
        .await?;
    }

    let (declared_file_count, declared_total_bytes) = match setup_step(
        APPROVAL_TIMEOUT,
        "read transfer offer",
        read_message(stream),
    )
    .await?
    {
        WireMessage::OfferStart {
            transfer_id: offered,
            file_count,
            total_bytes,
        } if offered == transfer_id => (file_count, total_bytes),
        other => return Err(anyhow!("invalid transfer offer: {other:?}")),
    };

    if declared_file_count > MAX_MANIFEST_ENTRIES {
        return reject_offer(stream, &transfer_id, "manifest has too many files").await;
    }

    let mut wire_entries = Vec::new();
    loop {
        match setup_step(
            Duration::from_secs(30),
            "read manifest",
            read_message(stream),
        )
        .await?
        {
            WireMessage::ManifestBatch {
                transfer_id: batch_id,
                entries,
            } if batch_id == transfer_id => {
                wire_entries.extend(entries);
                if wire_entries.len() > MAX_MANIFEST_ENTRIES as usize {
                    return reject_offer(stream, &transfer_id, "manifest has too many entries")
                        .await;
                }
            }
            WireMessage::OfferEnd {
                transfer_id: end_id,
            } if end_id == transfer_id => break,
            other => return Err(anyhow!("invalid manifest message: {other:?}")),
        }
    }

    let entries = wire_entries
        .iter()
        .map(WireManifestEntry::to_manifest_entry)
        .collect::<std::io::Result<Vec<_>>>()
        .context("decode manifest")?;
    let manifest = crate::core::TransferManifest::new(entries).context("validate manifest")?;
    let actual_file_count = manifest
        .entries
        .iter()
        .filter(|entry| !entry.is_directory)
        .count() as u64;
    if actual_file_count != declared_file_count || manifest.total_bytes != declared_total_bytes {
        return reject_offer(stream, &transfer_id, "manifest totals do not match").await;
    }

    let _transfer_slot = transfer_slots
        .acquire_owned()
        .await
        .context("receiver stopped")?;
    let _active_receive = engine.begin_receive();
    prepare_directories(&output_directory, &manifest).await?;
    let checkpoint_root = database::checkpoints_directory();
    let resume_entries =
        build_receiver_resume_entries(&output_directory, &manifest, &transfer_id, &checkpoint_root)
            .await?;
    write_message(
        stream,
        &WireMessage::Accept {
            transfer_id: transfer_id.clone(),
            resume: resume_entries.clone(),
        },
    )
    .await
    .context("accept transfer")?;

    let pool = engine
        .buffer_pool()
        .context("create receiver buffer pool")?;
    let _ = events.send(TransferEvent::Started {
        direction: TransferDirection::Receiving,
        transfer_id: transfer_id.clone(),
        file_count: actual_file_count,
        total_bytes: manifest.total_bytes,
        peer: format!("{device_name} ({peer})"),
    });

    let expected_files = manifest
        .entries
        .iter()
        .filter(|entry| !entry.is_directory)
        .map(|entry| {
            (
                path_to_wire(&entry.relative_path).expect("validated path"),
                entry.size_bytes,
            )
        })
        .collect::<HashMap<_, _>>();
    let resume_offsets = resume_entries
        .iter()
        .map(|entry| (entry.relative_path.clone(), entry.offset_bytes))
        .collect::<HashMap<_, _>>();
    let mut received_files = HashSet::new();
    let started = Instant::now();
    let mut bytes_transferred = 0_u64;

    for _ in 0..actual_file_count {
        control
            .wait_if_paused()
            .await
            .context("wait before receive")?;
        let (relative_path, size_bytes, offset_bytes) =
            match read_message(stream).await.context("read file header")? {
                WireMessage::FileStart {
                    transfer_id: file_id,
                    relative_path,
                    size_bytes,
                    offset_bytes,
                } if file_id == transfer_id => (relative_path, size_bytes, offset_bytes),
                other => return Err(anyhow!("invalid file header: {other:?}")),
            };
        if !received_files.insert(relative_path.clone()) {
            return Err(anyhow!("file was sent more than once: {relative_path}"));
        }
        if expected_files.get(&relative_path) != Some(&size_bytes) {
            return Err(anyhow!(
                "file is not present in accepted manifest: {relative_path}"
            ));
        }
        let expected_offset = resume_offsets
            .get(&relative_path)
            .copied()
            .unwrap_or_default();
        if offset_bytes != expected_offset || offset_bytes > size_bytes {
            return Err(anyhow!(
                "invalid resume offset for {relative_path}: expected {expected_offset}, got {offset_bytes}"
            ));
        }

        let relative = crate::core::validate_relative_path(Path::new(&relative_path))?;
        let destination = safe_destination(&output_directory, &relative)?;
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow!("destination has no parent"))?;
        fs::create_dir_all(parent).await?;
        ensure_parent_stays_under_root(&output_directory, parent)?;
        let temporary = destination.with_extension(format!("russ-part-{transfer_id}"));
        let destination_exists = has_path(&destination).await?;
        let use_existing_destination = offset_bytes == size_bytes && destination_exists;
        if use_existing_destination {
            let metadata = fs::symlink_metadata(&destination).await?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(anyhow!(
                    "resume destination is not a regular file: {}",
                    destination.display()
                ));
            }
            if metadata.len() != size_bytes {
                return Err(anyhow!(
                    "resume destination size changed: {}",
                    destination.display()
                ));
            }
        } else {
            if destination_exists {
                return Err(anyhow!(
                    "destination already exists: {}",
                    destination.display()
                ));
            }
            let mut file = open_partial_file(&temporary, offset_bytes).await?;
            let progress = ContentProgress {
                pool: &pool,
                control: &control,
                events: &events,
                direction: TransferDirection::Receiving,
                transfer_id: &transfer_id,
                relative_path: &relative_path,
                bytes_before_file: bytes_transferred.saturating_add(offset_bytes),
                total_bytes: manifest.total_bytes,
                started,
            };
            let receive_result = receive_file_contents(
                stream,
                &mut file,
                size_bytes,
                offset_bytes,
                &progress,
                &CheckpointContext {
                    root: &checkpoint_root,
                    transfer_id: &transfer_id,
                    relative_path: &relative_path,
                },
            )
            .await;
            file.flush().await.ok();
            drop(file);
            let (received, digest, metrics) = match receive_result {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            engine.observe(metrics.sample(received, false));
            bytes_transferred = bytes_transferred
                .saturating_add(offset_bytes)
                .saturating_add(received);

            match read_message(stream).await.context("read sender digest")? {
                WireMessage::FileComplete {
                    transfer_id: complete_id,
                    relative_path: complete_path,
                    sha256,
                } if complete_id == transfer_id
                    && complete_path == relative_path
                    && sha256 == digest => {}
                other => {
                    return Err(anyhow!("file integrity check failed: {other:?}"));
                }
            }

            if has_path(&destination).await? {
                return Err(anyhow!(
                    "destination appeared during transfer: {}",
                    destination.display()
                ));
            }
            fs::rename(&temporary, &destination)
                .await
                .with_context(|| format!("commit {}", destination.display()))?;
        }

        if use_existing_destination {
            let digest = sha256_file(&destination).await?;
            bytes_transferred = bytes_transferred.saturating_add(offset_bytes);
            match read_message(stream).await.context("read sender digest")? {
                WireMessage::FileComplete {
                    transfer_id: complete_id,
                    relative_path: complete_path,
                    sha256,
                } if complete_id == transfer_id
                    && complete_path == relative_path
                    && sha256 == digest => {}
                other => {
                    return Err(anyhow!("existing file integrity check failed: {other:?}"));
                }
            }
        }

        remove_checkpoint(&checkpoint_root, &transfer_id).await?;
        write_message(
            stream,
            &WireMessage::FileAck {
                transfer_id: transfer_id.clone(),
                relative_path,
            },
        )
        .await
        .context("acknowledge file")?;
    }

    match read_message(stream)
        .await
        .context("read sender completion")?
    {
        WireMessage::TransferComplete {
            transfer_id: complete_id,
            total_bytes,
        } if complete_id == transfer_id
            && total_bytes == bytes_transferred
            && received_files.len() == expected_files.len() => {}
        other => return Err(anyhow!("invalid transfer completion: {other:?}")),
    }
    write_message(
        stream,
        &WireMessage::TransferAck {
            transfer_id: transfer_id.clone(),
        },
    )
    .await
    .context("acknowledge transfer")?;
    let _ = events.send(TransferEvent::Completed {
        direction: TransferDirection::Receiving,
        transfer_id,
        bytes_transferred,
    });
    Ok(())
}

async fn reject_offer<S>(stream: &mut S, transfer_id: &str, reason: &str) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    write_message(
        stream,
        &WireMessage::Reject {
            transfer_id: transfer_id.to_owned(),
            reason: reason.to_owned(),
        },
    )
    .await
    .context("reject transfer")?;
    Err(anyhow!(reason.to_owned()))
}

async fn prepare_directories(
    output_directory: &Path,
    manifest: &crate::core::TransferManifest,
) -> Result<()> {
    for entry in &manifest.entries {
        if !entry.is_directory {
            continue;
        }
        let destination = safe_destination(output_directory, &entry.relative_path)?;
        if has_path(&destination).await? {
            if !fs::metadata(&destination).await?.is_dir() {
                return Err(anyhow!(
                    "directory destination is a file: {}",
                    destination.display()
                ));
            }
        } else {
            fs::create_dir_all(&destination).await?;
        }
        ensure_parent_stays_under_root(output_directory, &destination)?;
    }
    Ok(())
}

async fn send_file_contents<S>(
    stream: &mut S,
    source: &Path,
    size_bytes: u64,
    offset_bytes: u64,
    progress: &ContentProgress<'_>,
) -> Result<(u64, String, StreamMetrics)>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if offset_bytes > size_bytes {
        return Err(anyhow!("resume offset exceeds source size"));
    }
    let mut file = File::open(source).await?;
    let mut lease = progress.pool.acquire().await?;
    let mut hasher = Sha256::new();
    let mut prefix_remaining = offset_bytes;
    file.seek(SeekFrom::Start(0)).await?;
    while prefix_remaining > 0 {
        let to_read = prefix_remaining.min(lease.len() as u64) as usize;
        let read = file.read(&mut lease.as_mut_slice()[..to_read]).await?;
        if read == 0 {
            return Err(anyhow!("source ended inside resume prefix"));
        }
        hasher.update(&lease.as_mut_slice()[..read]);
        prefix_remaining -= read as u64;
    }
    file.seek(SeekFrom::Start(offset_bytes)).await?;
    let started = Instant::now();
    let mut read_wait = std::time::Duration::ZERO;
    let mut write_wait = std::time::Duration::ZERO;
    let mut remaining = size_bytes - offset_bytes;
    let mut file_bytes = 0_u64;
    while remaining > 0 {
        progress.control.wait_if_paused().await?;
        let to_read = remaining.min(lease.len() as u64) as usize;
        let read_started = Instant::now();
        let read = file.read(&mut lease.as_mut_slice()[..to_read]).await?;
        read_wait += read_started.elapsed();
        if read == 0 {
            return Err(anyhow!("source ended before its declared size"));
        }
        let write_started = Instant::now();
        stream.write_all(&lease.as_mut_slice()[..read]).await?;
        write_wait += write_started.elapsed();
        hasher.update(&lease.as_mut_slice()[..read]);
        remaining -= read as u64;
        file_bytes += read as u64;
        let bytes_transferred = progress.bytes_before_file + file_bytes;
        emit_progress(progress, bytes_transferred);
    }
    Ok((
        file_bytes,
        format!("{:x}", hasher.finalize()),
        StreamMetrics {
            elapsed: started.elapsed(),
            read_wait,
            write_wait,
        },
    ))
}

async fn receive_file_contents<S>(
    stream: &mut S,
    destination: &mut File,
    size_bytes: u64,
    offset_bytes: u64,
    progress: &ContentProgress<'_>,
    checkpoint: &CheckpointContext<'_>,
) -> Result<(u64, String, StreamMetrics)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    if offset_bytes > size_bytes {
        return Err(anyhow!("resume offset exceeds destination size"));
    }
    let mut lease = progress.pool.acquire().await?;
    let mut hasher = Sha256::new();
    let mut prefix_remaining = offset_bytes;
    destination.seek(SeekFrom::Start(0)).await?;
    while prefix_remaining > 0 {
        let to_read = prefix_remaining.min(lease.len() as u64) as usize;
        let read = destination
            .read(&mut lease.as_mut_slice()[..to_read])
            .await?;
        if read == 0 {
            return Err(anyhow!("partial destination ended inside resume prefix"));
        }
        hasher.update(&lease.as_mut_slice()[..read]);
        prefix_remaining -= read as u64;
    }
    destination.seek(SeekFrom::Start(offset_bytes)).await?;
    let started = Instant::now();
    let mut read_wait = std::time::Duration::ZERO;
    let mut write_wait = std::time::Duration::ZERO;
    let mut remaining = size_bytes - offset_bytes;
    let mut file_bytes = 0_u64;
    let mut last_checkpoint_bytes = offset_bytes;
    let mut last_checkpoint_at = Instant::now();
    while remaining > 0 {
        progress.control.wait_if_paused().await?;
        let to_read = remaining.min(lease.len() as u64) as usize;
        let read_started = Instant::now();
        let read = stream.read(&mut lease.as_mut_slice()[..to_read]).await?;
        read_wait += read_started.elapsed();
        if read == 0 {
            return Err(anyhow!("sender ended before its declared size"));
        }
        let write_started = Instant::now();
        destination.write_all(&lease.as_mut_slice()[..read]).await?;
        write_wait += write_started.elapsed();
        hasher.update(&lease.as_mut_slice()[..read]);
        remaining -= read as u64;
        file_bytes += read as u64;
        let bytes_transferred = progress.bytes_before_file + file_bytes;
        emit_progress(progress, bytes_transferred);
        let completed_bytes = offset_bytes.saturating_add(file_bytes);
        if completed_bytes.saturating_sub(last_checkpoint_bytes) >= CHECKPOINT_INTERVAL_BYTES
            || last_checkpoint_at.elapsed().as_secs() >= 1
        {
            let saved_checkpoint = ResumeCheckpoint::new(
                checkpoint.transfer_id,
                checkpoint.relative_path,
                completed_bytes,
                size_bytes,
                None,
            )?;
            save_checkpoint(checkpoint.root, &saved_checkpoint).await?;
            last_checkpoint_bytes = completed_bytes;
            last_checkpoint_at = Instant::now();
        }
    }
    Ok((
        file_bytes,
        format!("{:x}", hasher.finalize()),
        StreamMetrics {
            elapsed: started.elapsed(),
            read_wait,
            write_wait,
        },
    ))
}

fn emit_progress(progress: &ContentProgress<'_>, bytes_transferred: u64) {
    let elapsed = progress.started.elapsed().as_secs_f64();
    let bytes_per_second = if elapsed > 0.0 {
        bytes_transferred as f64 / elapsed
    } else {
        0.0
    };
    let _ = progress.events.send(TransferEvent::Progress {
        direction: progress.direction,
        transfer_id: progress.transfer_id.to_owned(),
        current_path: progress.relative_path.to_owned(),
        bytes_transferred,
        total_bytes: progress.total_bytes,
        bytes_per_second,
    });
}

async fn has_path(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn open_partial_file(path: &Path, offset_bytes: u64) -> Result<File> {
    let exists = has_path(path).await?;
    if exists {
        let metadata = fs::symlink_metadata(path).await?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(anyhow!("partial destination is not a regular file"));
        }
        if metadata.len() != offset_bytes {
            return Err(anyhow!(
                "partial destination length does not match resume offset"
            ));
        }
    } else if offset_bytes != 0 {
        return Err(anyhow!(
            "resume offset was advertised without a partial destination"
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    if offset_bytes == 0 {
        options.truncate(true);
    }
    let mut file = options
        .open(path)
        .await
        .with_context(|| format!("open partial file {}", path.display()))?;
    file.seek(SeekFrom::Start(offset_bytes)).await?;
    Ok(file)
}

fn build_resume_offsets(
    manifest: &TransferManifest,
    resume: Vec<WireResumeEntry>,
) -> Result<HashMap<String, u64>> {
    let expected = manifest
        .entries
        .iter()
        .filter(|entry| !entry.is_directory)
        .map(|entry| {
            (
                path_to_wire(&entry.relative_path).expect("validated manifest path"),
                entry.size_bytes,
            )
        })
        .collect::<HashMap<_, _>>();
    let mut offsets = HashMap::new();
    for entry in resume {
        let normalized = path_to_wire(Path::new(&entry.relative_path))?;
        if normalized != entry.relative_path {
            return Err(anyhow!("receiver returned a non-canonical resume path"));
        }
        let Some(size_bytes) = expected.get(&entry.relative_path) else {
            return Err(anyhow!(
                "receiver requested resume for an unknown file: {}",
                entry.relative_path
            ));
        };
        if entry.offset_bytes > *size_bytes {
            return Err(anyhow!(
                "receiver resume offset exceeds file size: {}",
                entry.relative_path
            ));
        }
        if offsets
            .insert(entry.relative_path.clone(), entry.offset_bytes)
            .is_some()
        {
            return Err(anyhow!("receiver repeated a resume path"));
        }
    }
    Ok(offsets)
}

async fn build_receiver_resume_entries(
    output_directory: &Path,
    manifest: &TransferManifest,
    transfer_id: &str,
    checkpoint_root: &Path,
) -> Result<Vec<WireResumeEntry>> {
    let checkpoint = load_checkpoint(checkpoint_root, transfer_id).await?;
    let mut resume = Vec::new();
    for entry in manifest.entries.iter().filter(|entry| !entry.is_directory) {
        let relative_path = path_to_wire(&entry.relative_path)?;
        let relative = crate::core::validate_relative_path(Path::new(&relative_path))?;
        let destination = safe_destination(output_directory, &relative)?;
        if has_path(&destination).await? {
            let metadata = fs::symlink_metadata(&destination).await?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(anyhow!(
                    "destination already exists and is not a regular file: {}",
                    destination.display()
                ));
            }
            if metadata.len() == entry.size_bytes {
                resume.push(WireResumeEntry {
                    relative_path,
                    offset_bytes: entry.size_bytes,
                });
            }
            continue;
        }

        let temporary = partial_path(&destination, transfer_id);
        if !has_path(&temporary).await? {
            continue;
        }
        let metadata = fs::symlink_metadata(&temporary).await?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(anyhow!("partial destination is not a regular file"));
        }
        if metadata.len() > entry.size_bytes {
            return Err(anyhow!("partial destination exceeds source file size"));
        }
        if let Some(checkpoint) = &checkpoint {
            if checkpoint.relative_path == relative
                && checkpoint.total_bytes == entry.size_bytes
                && checkpoint.completed_bytes > metadata.len()
            {
                warn!(
                    transfer_id,
                    path = %relative_path,
                    checkpoint_bytes = checkpoint.completed_bytes,
                    file_bytes = metadata.len(),
                    "checkpoint is ahead of partial file; resuming from durable file length"
                );
            }
        }
        resume.push(WireResumeEntry {
            relative_path,
            offset_bytes: metadata.len(),
        });
    }
    Ok(resume)
}

fn partial_path(destination: &Path, transfer_id: &str) -> PathBuf {
    destination.with_extension(format!("russ-part-{transfer_id}"))
}

fn ensure_parent_stays_under_root(root: &Path, path: &Path) -> Result<()> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("canonicalize receive root {}", root.display()))?;
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("canonicalize receive path {}", path.display()))?;
    if canonical_path.starts_with(&canonical_root) {
        Ok(())
    } else {
        Err(anyhow!(
            "destination escapes receive root: {}",
            path.display()
        ))
    }
}

fn path_to_wire(path: &Path) -> Result<String> {
    let validated = crate::core::validate_relative_path(path)?;
    Ok(validated.to_string_lossy().replace('\\', "/"))
}

fn transfer_session_id(
    source: &Path,
    manifest: &TransferManifest,
    identity: &DeviceIdentity,
    peer_device_id: &str,
    peer_fingerprint: &str,
) -> Result<String> {
    let mut hasher = Sha256::new();
    let source = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    let source_string = source.to_string_lossy().into_owned();
    let manifest_bytes = serde_json::to_vec(manifest).context("serialize transfer manifest")?;
    for value in [
        identity.device_id.as_bytes(),
        peer_device_id.as_bytes(),
        peer_fingerprint.as_bytes(),
        source_string.as_bytes(),
        &manifest_bytes,
    ] {
        hasher.update(value);
        hasher.update([0]);
    }
    Ok(format!("russ-{:x}", hasher.finalize()))
}

fn identity_fingerprint(identity: &DeviceIdentity) -> Result<String> {
    let certificate = identity
        .certificate()
        .map_err(|error| anyhow!("read local device certificate: {error}"))?;
    Ok(security::certificate_fingerprint(&certificate))
}

fn peer_certificate_fingerprint(certificates: Option<&[CertificateDer<'_>]>) -> Result<String> {
    let certificate = certificates
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| anyhow!("peer did not present a certificate"))?;
    Ok(security::certificate_fingerprint(certificate))
}

fn is_trusted(friends: &[SavedFriend], device_id: &str, fingerprint: &str) -> bool {
    friends.iter().any(|friend| {
        friend.trusted
            && friend.device_id == device_id
            && security::normalize_fingerprint(&friend.certificate_fingerprint).as_deref()
                == Some(fingerprint)
    })
}

async fn request_approval(
    events: &UnboundedSender<TransferEvent>,
    request: ApprovalRequest<'_>,
) -> Result<()> {
    let (responder, decision) = oneshot::channel();
    events
        .send(TransferEvent::ApprovalRequested {
            direction: request.direction,
            transfer_id: request.transfer_id.to_owned(),
            device_id: request.device_id.to_owned(),
            device_name: request.device_name.to_owned(),
            operating_system: request.operating_system.to_owned(),
            certificate_fingerprint: request.certificate_fingerprint.to_owned(),
            peer: request.peer.to_owned(),
            responder,
        })
        .map_err(|_| anyhow!("approval UI is no longer available"))?;
    if time::timeout(APPROVAL_TIMEOUT, decision)
        .await
        .context("device approval timed out after 5 minutes")?
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(anyhow!("device approval was rejected"))
    }
}
