use russ::core::{
    streaming::copy_stream, AdaptiveOptimizer, BufferPool, OptimizerConfig, ThroughputSample,
    TransferControl,
};
use russ::hardware::HardwareSnapshot;
use russ::network::bind_tcp_listener;
use russ::network::{run_receiver, send_path, TransferDirection, TransferEvent, TransferSecurity};
use russ::security::DeviceIdentity;
use russ::storage::SavedFriend;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn bounded_stream_copy_preserves_data() {
    let mut source_profile = HardwareSnapshot::default();
    source_profile.cpu.logical_cores = 8;
    source_profile.memory.available_bytes = 512 * 1024 * 1024;
    let optimizer = AdaptiveOptimizer::new(source_profile, OptimizerConfig::default());
    let pool = BufferPool::new(optimizer.plan()).expect("valid bounded plan");
    assert!(pool.max_in_flight_bytes() <= 64 * 1024 * 1024);

    let control = TransferControl::default();
    let payload = (0..200_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let expected = payload.clone();

    let (mut source_writer, mut source_reader) = tokio::io::duplex(4096);
    let source_task = tokio::spawn(async move {
        source_writer.write_all(&payload).await?;
        source_writer.shutdown().await
    });

    let (mut destination_reader, mut destination_writer) = tokio::io::duplex(4096);
    let destination_task = tokio::spawn(async move {
        let mut output = Vec::new();
        destination_reader.read_to_end(&mut output).await?;
        Ok::<_, std::io::Error>(output)
    });

    let stats = copy_stream(
        &mut source_reader,
        &mut destination_writer,
        &pool,
        &control,
        |_| {},
    )
    .await
    .expect("copy stream");
    destination_writer
        .shutdown()
        .await
        .expect("close destination stream");
    source_task
        .await
        .expect("source task")
        .expect("source write");
    let received = destination_task
        .await
        .expect("destination task")
        .expect("destination read");

    assert_eq!(stats.bytes_copied, expected.len() as u64);
    assert_eq!(received, expected);
}

#[test]
fn optimizer_reacts_to_backpressure_without_exceeding_bounds() {
    let mut profile = HardwareSnapshot::default();
    profile.cpu.logical_cores = 4;
    profile.memory.available_bytes = 2 * 1024 * 1024 * 1024;
    let config = OptimizerConfig::default();
    let mut optimizer = AdaptiveOptimizer::new(profile, config.clone());
    let original = optimizer.plan().buffer_size_bytes;

    optimizer.observe(ThroughputSample {
        elapsed: Duration::from_secs(1),
        bytes: 10 * 1024 * 1024,
        backpressure_ratio: 0.8,
        io_wait_ratio: 0.1,
    });

    assert!(optimizer.plan().buffer_size_bytes <= original);
    assert!(optimizer.plan().buffer_size_bytes >= config.min_buffer_bytes);
    assert!(optimizer.plan().max_in_flight_bytes <= config.max_in_flight_bytes);
}

#[tokio::test]
async fn socket_factory_binds_a_tokio_tcp_listener() {
    let address: SocketAddr = "127.0.0.1:0".parse().expect("socket address");
    let listener = bind_tcp_listener(address).expect("bind TCP listener");
    assert_ne!(listener.local_addr().expect("local address").port(), 0);
}

#[tokio::test]
async fn tls_phase4_transfers_files_and_empty_directories() {
    let source_root = tempfile::tempdir().expect("source root");
    let source_folder = source_root.path().join("bundle");
    tokio::fs::create_dir_all(source_folder.join("empty"))
        .await
        .expect("empty directory");
    tokio::fs::write(source_folder.join("hello.txt"), b"hello over TCP")
        .await
        .expect("source file");
    let destination_root = tempfile::tempdir().expect("destination root");

    let mut profile = HardwareSnapshot::default();
    profile.cpu.logical_cores = 4;
    profile.memory.available_bytes = 512 * 1024 * 1024;
    let engine = russ::core::TransferEngine::new(profile, OptimizerConfig::default());
    let receiver_identity = DeviceIdentity::new("test receiver").expect("receiver identity");
    let sender_identity = DeviceIdentity::new("test sender").expect("sender identity");
    let receiver_fingerprint = receiver_identity
        .certificate_fingerprint
        .clone()
        .expect("receiver fingerprint");
    let sender_fingerprint = sender_identity
        .certificate_fingerprint
        .clone()
        .expect("sender fingerprint");
    let receiver_trust = SavedFriend {
        device_name: "test sender".to_owned(),
        device_id: sender_identity.device_id.clone(),
        certificate_fingerprint: sender_fingerprint.clone(),
        trusted: true,
        ..Default::default()
    };
    let sender_trust = SavedFriend {
        device_name: "test receiver".to_owned(),
        device_id: receiver_identity.device_id.clone(),
        certificate_fingerprint: receiver_fingerprint.clone(),
        trusted: true,
        ..Default::default()
    };
    let receiver_security = TransferSecurity {
        identity: receiver_identity,
        operating_system: "test OS".to_owned(),
        trusted_friends: vec![receiver_trust],
        expected_peer_fingerprint: None,
    };
    let receiver_control = TransferControl::default();
    let (events, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let receiver_task = tokio::spawn(run_receiver(
        "127.0.0.1:0".parse().expect("bind address"),
        destination_root.path().to_path_buf(),
        receiver_security,
        engine.clone(),
        events.clone(),
        receiver_control.clone(),
    ));

    let receiver_address = loop {
        let event = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("receiver should start")
            .expect("receiver event");
        if let TransferEvent::Listening { address } = event {
            break address;
        }
    };

    send_path(
        receiver_address,
        source_folder,
        TransferSecurity {
            identity: sender_identity,
            operating_system: "test OS".to_owned(),
            trusted_friends: vec![sender_trust],
            expected_peer_fingerprint: Some(receiver_fingerprint),
        },
        engine,
        events,
        TransferControl::default(),
    )
    .await
    .expect("send over TCP");

    let mut received = false;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(3), event_rx.recv()).await
    {
        if let TransferEvent::Completed {
            direction: TransferDirection::Receiving,
            ..
        } = event
        {
            received = true;
            break;
        }
    }
    assert!(received, "receiver should report completion");

    receiver_control.cancel();
    receiver_task
        .await
        .expect("receiver task")
        .expect("receiver should stop cleanly");
    assert_eq!(
        tokio::fs::read(destination_root.path().join("bundle/hello.txt"))
            .await
            .expect("received file"),
        b"hello over TCP"
    );
    assert!(
        tokio::fs::metadata(destination_root.path().join("bundle/empty"))
            .await
            .expect("received empty folder")
            .is_dir()
    );
}

#[tokio::test]
async fn unknown_tls_peer_requires_explicit_approval() {
    let source_root = tempfile::tempdir().expect("source root");
    let source_file = source_root.path().join("approval.txt");
    tokio::fs::write(&source_file, b"approval-gated transfer")
        .await
        .expect("source file");
    let destination_root = tempfile::tempdir().expect("destination root");

    let mut profile = HardwareSnapshot::default();
    profile.cpu.logical_cores = 4;
    profile.memory.available_bytes = 512 * 1024 * 1024;
    let engine = russ::core::TransferEngine::new(profile, OptimizerConfig::default());
    let receiver_identity = DeviceIdentity::new("approval receiver").expect("receiver identity");
    let sender_identity = DeviceIdentity::new("approval sender").expect("sender identity");
    let receiver_control = TransferControl::default();
    let (events, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let receiver_task = tokio::spawn(run_receiver(
        "127.0.0.1:0".parse().expect("bind address"),
        destination_root.path().to_path_buf(),
        TransferSecurity {
            identity: receiver_identity,
            operating_system: "test OS".to_owned(),
            trusted_friends: Vec::new(),
            expected_peer_fingerprint: None,
        },
        engine.clone(),
        events.clone(),
        receiver_control.clone(),
    ));

    let receiver_address = loop {
        let event = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("receiver should start")
            .expect("receiver event");
        if let TransferEvent::Listening { address } = event {
            break address;
        }
    };

    let mut sender_task = tokio::spawn(send_path(
        receiver_address,
        source_file,
        TransferSecurity {
            identity: sender_identity,
            operating_system: "test OS".to_owned(),
            trusted_friends: Vec::new(),
            expected_peer_fingerprint: None,
        },
        engine,
        events,
        TransferControl::default(),
    ));
    let mut sender_done = false;
    let mut receiver_done = false;
    let mut approvals = 0;
    let mut approval_responses = Vec::new();
    while !(sender_done && receiver_done) {
        tokio::select! {
            result = &mut sender_task, if !sender_done => {
                result.expect("sender task").expect("approved sender transfer");
                sender_done = true;
            }
            event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv()) => match event.expect("identity/approval exchange must not deadlock").expect("transfer event") {
                TransferEvent::ApprovalRequested { responder, .. } => {
                    approvals += 1;
                    approval_responses.push(responder);
                    if approvals == 2 {
                        for response in approval_responses.drain(..) {
                            response.send(true).expect("approval response");
                        }
                    }
                }
                TransferEvent::Completed { direction: TransferDirection::Receiving, .. } => {
                    receiver_done = true;
                }
                TransferEvent::Failed { error, .. } => panic!("unexpected transfer failure: {error}"),
                _ => {}
            }
        }
    }
    assert_eq!(approvals, 2, "both peers must approve the unknown device");

    receiver_control.cancel();
    receiver_task
        .await
        .expect("receiver task")
        .expect("receiver should stop cleanly");
    assert_eq!(
        tokio::fs::read(destination_root.path().join("approval.txt"))
            .await
            .expect("received file"),
        b"approval-gated transfer"
    );
}

#[tokio::test]
async fn interrupted_transfer_resumes_from_receiver_partial_file() {
    let source_root = tempfile::tempdir().expect("source root");
    let source_file = source_root.path().join("large.bin");
    let payload = (0..(8 * 1024 * 1024))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    tokio::fs::write(&source_file, &payload)
        .await
        .expect("source file");
    let destination_root = tempfile::tempdir().expect("destination root");

    let mut profile = HardwareSnapshot::default();
    profile.cpu.logical_cores = 4;
    profile.memory.available_bytes = 512 * 1024 * 1024;
    let engine = russ::core::TransferEngine::new(profile, OptimizerConfig::default());
    let receiver_identity = DeviceIdentity::new("resume receiver").expect("receiver identity");
    let sender_identity = DeviceIdentity::new("resume sender").expect("sender identity");
    let receiver_fingerprint = receiver_identity
        .certificate_fingerprint
        .clone()
        .expect("receiver fingerprint");
    let sender_fingerprint = sender_identity
        .certificate_fingerprint
        .clone()
        .expect("sender fingerprint");
    let receiver_trust = SavedFriend {
        device_name: "resume sender".to_owned(),
        device_id: sender_identity.device_id.clone(),
        certificate_fingerprint: sender_fingerprint,
        trusted: true,
        ..Default::default()
    };
    let sender_trust = SavedFriend {
        device_name: "resume receiver".to_owned(),
        device_id: receiver_identity.device_id.clone(),
        certificate_fingerprint: receiver_fingerprint.clone(),
        trusted: true,
        ..Default::default()
    };
    let receiver_control = TransferControl::default();
    let (events, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let receiver_task = tokio::spawn(run_receiver(
        "127.0.0.1:0".parse().expect("bind address"),
        destination_root.path().to_path_buf(),
        TransferSecurity {
            identity: receiver_identity.clone(),
            operating_system: "test OS".to_owned(),
            trusted_friends: vec![receiver_trust],
            expected_peer_fingerprint: None,
        },
        engine.clone(),
        events.clone(),
        receiver_control.clone(),
    ));

    let receiver_address = loop {
        let event = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("receiver should start")
            .expect("receiver event");
        if let TransferEvent::Listening { address } = event {
            break address;
        }
    };

    let sender_control = TransferControl::default();
    let mut first_sender = tokio::spawn(send_path(
        receiver_address,
        source_file.clone(),
        TransferSecurity {
            identity: sender_identity.clone(),
            operating_system: "test OS".to_owned(),
            trusted_friends: vec![sender_trust.clone()],
            expected_peer_fingerprint: Some(receiver_fingerprint.clone()),
        },
        engine.clone(),
        events.clone(),
        sender_control.clone(),
    ));
    let first_result = loop {
        tokio::select! {
            result = &mut first_sender => {
                break result.expect("first sender task");
            }
            event = event_rx.recv() => {
                match event.expect("transfer event") {
                    TransferEvent::Progress {
                        direction: TransferDirection::Sending,
                        bytes_transferred,
                        ..
                    } if bytes_transferred > 0 => sender_control.cancel(),
                    _ => {}
                }
            }
        }
    };
    assert!(
        first_result.is_err(),
        "the first transfer should be interrupted"
    );
    assert!(
        tokio::fs::metadata(destination_root.path().join("large.bin"))
            .await
            .is_err(),
        "an interrupted file must not be committed"
    );
    loop {
        let event = tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
            .await
            .expect("receiver should finish the interrupted connection")
            .expect("receiver event");
        if matches!(
            event,
            TransferEvent::Failed {
                direction: TransferDirection::Receiving,
                ..
            }
        ) {
            break;
        }
    }

    let resumed_result = send_path(
        receiver_address,
        source_file,
        TransferSecurity {
            identity: sender_identity,
            operating_system: "test OS".to_owned(),
            trusted_friends: vec![sender_trust],
            expected_peer_fingerprint: Some(receiver_fingerprint),
        },
        engine,
        events,
        TransferControl::default(),
    )
    .await;
    resumed_result.expect("resumed transfer");

    let mut received = false;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(3), event_rx.recv()).await
    {
        if let TransferEvent::Completed {
            direction: TransferDirection::Receiving,
            ..
        } = event
        {
            received = true;
            break;
        }
    }
    assert!(received, "receiver should report resumed completion");

    receiver_control.cancel();
    receiver_task
        .await
        .expect("receiver task")
        .expect("receiver should stop cleanly");
    assert_eq!(
        tokio::fs::read(destination_root.path().join("large.bin"))
            .await
            .expect("received file"),
        payload
    );
}

struct ConnectionFixture {
    _roots: Vec<tempfile::TempDir>,
    source: std::path::PathBuf,
    address: SocketAddr,
    engine: russ::core::TransferEngine,
    sender: TransferSecurity,
    events: tokio::sync::mpsc::UnboundedSender<TransferEvent>,
    event_rx: tokio::sync::mpsc::UnboundedReceiver<TransferEvent>,
    receiver_control: TransferControl,
}

impl Drop for ConnectionFixture {
    fn drop(&mut self) {
        self.receiver_control.cancel();
    }
}

async fn connection_fixture() -> ConnectionFixture {
    let source_root = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let source = source_root.path().join("connection-test.txt");
    tokio::fs::write(&source, b"connection reliability")
        .await
        .unwrap();
    let mut profile = HardwareSnapshot::default();
    profile.cpu.logical_cores = 1;
    profile.memory.available_bytes = 128 * 1024 * 1024;
    let engine = russ::core::TransferEngine::new(profile, OptimizerConfig::default());
    let receiver = DeviceIdentity::new("receiver").unwrap();
    let sender = DeviceIdentity::new("sender").unwrap();
    let trust = |identity: &DeviceIdentity| SavedFriend {
        device_id: identity.device_id.clone(),
        certificate_fingerprint: identity.certificate_fingerprint.clone().unwrap(),
        trusted: true,
        ..Default::default()
    };
    let receiver_security = TransferSecurity {
        identity: receiver.clone(),
        operating_system: "test".into(),
        trusted_friends: vec![trust(&sender)],
        expected_peer_fingerprint: None,
    };
    let sender_security = TransferSecurity {
        identity: sender,
        operating_system: "test".into(),
        trusted_friends: vec![trust(&receiver)],
        expected_peer_fingerprint: receiver.certificate_fingerprint,
    };
    let control = TransferControl::default();
    let (events, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_receiver(
        "127.0.0.1:0".parse().unwrap(),
        destination.path().to_owned(),
        receiver_security,
        engine.clone(),
        events.clone(),
        control.clone(),
    ));
    let address = loop {
        if let TransferEvent::Listening { address } =
            tokio::time::timeout(Duration::from_secs(3), event_rx.recv())
                .await
                .unwrap()
                .unwrap()
        {
            break address;
        }
    };
    ConnectionFixture {
        _roots: vec![source_root, destination],
        source,
        address,
        engine,
        sender: sender_security,
        events,
        event_rx,
        receiver_control: control,
    }
}

#[tokio::test]
async fn stalled_handshakes_do_not_block_repeated_connections() {
    let fixture = connection_fixture().await;
    let mut stalled = Vec::new();
    for _ in 0..8 {
        stalled.push(
            tokio::net::TcpStream::connect(fixture.address)
                .await
                .unwrap(),
        );
    }
    tokio::time::timeout(Duration::from_secs(4), async {
        for _ in 0..20 {
            send_path(
                fixture.address,
                fixture.source.clone(),
                fixture.sender.clone(),
                fixture.engine.clone(),
                fixture.events.clone(),
                TransferControl::default(),
            )
            .await
            .unwrap();
        }
    })
    .await
    .expect("twenty legitimate connections must succeed while eight peers stall in TLS");
}

#[tokio::test]
async fn transient_tls_disconnect_is_retried_before_any_file_offer() {
    let fixture = connection_fixture().await;
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = proxy.local_addr().unwrap();
    let receiver = fixture.address;
    let proxy_task = tokio::spawn(async move {
        let (first, _) = proxy.accept().await.unwrap();
        drop(first); // simulate the first TLS handshake being interrupted
        let (mut client, _) = proxy.accept().await.unwrap();
        let mut upstream = tokio::net::TcpStream::connect(receiver).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });
    tokio::time::timeout(
        Duration::from_secs(4),
        send_path(
            address,
            fixture.source.clone(),
            fixture.sender.clone(),
            fixture.engine.clone(),
            fixture.events.clone(),
            TransferControl::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    proxy_task.abort();
}

#[tokio::test]
async fn cancellation_interrupts_a_stalled_tls_handshake() {
    let fixture = connection_fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let control = TransferControl::default();
    let sender = tokio::spawn(send_path(
        address,
        fixture.source.clone(),
        fixture.sender.clone(),
        fixture.engine.clone(),
        fixture.events.clone(),
        control.clone(),
    ));
    let (_silent_peer, _) = listener.accept().await.unwrap();
    control.cancel();
    let result = tokio::time::timeout(Duration::from_secs(1), sender)
        .await
        .unwrap()
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("cancelled"));
}

#[tokio::test]
async fn certificate_mismatch_is_not_retried_or_bypassed() {
    let mut fixture = connection_fixture().await;
    fixture.sender.expected_peer_fingerprint = Some("00".repeat(32));
    let error = send_path(
        fixture.address,
        fixture.source.clone(),
        fixture.sender.clone(),
        fixture.engine.clone(),
        fixture.events.clone(),
        TransferControl::default(),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("fingerprint mismatch"));
    let mut attempts = 0;
    while let Ok(event) = fixture.event_rx.try_recv() {
        if matches!(event, TransferEvent::Status { message, .. } if message.starts_with("Connecting to"))
        {
            attempts += 1;
        }
    }
    assert_eq!(attempts, 1);
}
