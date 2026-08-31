use std::time::Duration;

use netcatty_telnet::{
    COMMAND_CHANNEL_CAPACITY, TelnetCharset, TelnetCloseReason, TelnetRuntimeConfig,
    TelnetRuntimeError, TelnetRuntimeEvent, TelnetRuntimeManager, TelnetRuntimeSession,
    TelnetSessionId, command, option, suboption,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

async fn next_event(session: &mut TelnetRuntimeSession) -> TelnetRuntimeEvent {
    timeout(TEST_TIMEOUT, session.recv())
        .await
        .expect("runtime event timed out")
        .expect("runtime event channel closed early")
}

async fn expect_connect(session: &mut TelnetRuntimeSession) {
    assert!(matches!(
        next_event(session).await,
        TelnetRuntimeEvent::Connecting
    ));
    assert!(matches!(
        next_event(session).await,
        TelnetRuntimeEvent::Connected
    ));
}

async fn expect_data(session: &mut TelnetRuntimeSession, expected: &[u8]) {
    match next_event(session).await {
        TelnetRuntimeEvent::Data(data) => assert_eq!(data.as_slice(), expected),
        other => panic!("expected Data event, got {other:?}"),
    }
}

async fn wait_for_cleanup(manager: &TelnetRuntimeManager, session_id: &TelnetSessionId) {
    timeout(TEST_TIMEOUT, async {
        while manager.contains(session_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("session registry cleanup timed out");
}

async fn assert_no_socket_data(stream: &mut TcpStream) {
    let mut probe = [0_u8; 1];
    assert!(
        timeout(Duration::from_millis(120), stream.read(&mut probe))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_interaction_negotiation_resize_auto_login_and_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let manager = TelnetRuntimeManager::new();
    let config = TelnetRuntimeConfig::new(address.ip().to_string(), address.port(), 100, 40)
        .unwrap()
        .with_terminal_type("VT100")
        .unwrap()
        .with_username(" admin ")
        .unwrap()
        .with_password("s3cret")
        .unwrap()
        .with_startup_command("show version")
        .unwrap();
    let mut runtime = manager.start(config).unwrap();
    let session_id = runtime.session_id().clone();
    let (mut server, _) = timeout(TEST_TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    expect_connect(&mut runtime).await;

    server.write_all(b"Username: ").await.unwrap();
    let mut username = [0_u8; 7];
    timeout(TEST_TIMEOUT, server.read_exact(&mut username))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&username, b"admin\r\n");
    expect_data(&mut runtime, b"Username: ").await;

    server.write_all(b"\r\nPassword: ").await.unwrap();
    let mut password = [0_u8; 8];
    timeout(TEST_TIMEOUT, server.read_exact(&mut password))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&password, b"s3cret\r\n");
    expect_data(&mut runtime, b"\r\nPassword: ").await;

    server.write_all(b"\r\nrouter# ").await.unwrap();
    let mut startup = [0_u8; 14];
    timeout(TEST_TIMEOUT, server.read_exact(&mut startup))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&startup, b"show version\r\n");
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::AutoLoginCompleted
    ));
    expect_data(&mut runtime, b"\r\nrouter# ").await;
    server.write_all(b"\r\nrouter# ").await.unwrap();
    expect_data(&mut runtime, b"\r\nrouter# ").await;
    assert_no_socket_data(&mut server).await;

    // First IAC activates negotiation. The initial WILL NAWS is acknowledged
    // by DO and immediately followed by the retained 100x40 size.
    server
        .write_all(&[command::IAC, command::DO, option::NAWS])
        .await
        .unwrap();
    let mut activation = [0_u8; 18];
    timeout(TEST_TIMEOUT, server.read_exact(&mut activation))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        activation,
        [
            command::IAC,
            command::DO,
            option::SUPPRESS_GO_AHEAD,
            command::IAC,
            command::WILL,
            option::TERMINAL_TYPE,
            command::IAC,
            command::WILL,
            option::NAWS,
            command::IAC,
            command::SB,
            option::NAWS,
            0,
            100,
            0,
            40,
            command::IAC,
            command::SE,
        ]
    );

    server
        .write_all(&[
            command::IAC,
            command::DO,
            option::TERMINAL_TYPE,
            command::IAC,
            command::SB,
            option::TERMINAL_TYPE,
            suboption::SEND,
            command::IAC,
            command::SE,
        ])
        .await
        .unwrap();
    let expected_term = [
        command::IAC,
        command::SB,
        option::TERMINAL_TYPE,
        suboption::IS,
        b'V',
        b'T',
        b'1',
        b'0',
        b'0',
        command::IAC,
        command::SE,
    ];
    let mut term = [0_u8; 11];
    timeout(TEST_TIMEOUT, server.read_exact(&mut term))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(term, expected_term);

    manager.resize(&session_id, 255, 41).unwrap();
    let mut resized = [0_u8; 10];
    timeout(TEST_TIMEOUT, server.read_exact(&mut resized))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resized,
        [
            command::IAC,
            command::SB,
            option::NAWS,
            0,
            command::IAC,
            command::IAC,
            0,
            41,
            command::IAC,
            command::SE,
        ]
    );

    server
        .write_all(&[command::IAC, command::WILL, option::ECHO])
        .await
        .unwrap();
    let mut echo_ack = [0_u8; 3];
    timeout(TEST_TIMEOUT, server.read_exact(&mut echo_ack))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo_ack, [command::IAC, command::DO, option::ECHO]);
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::RemoteEcho { enabled: true }
    ));

    server
        .write_all(&[command::IAC, command::WONT, option::ECHO])
        .await
        .unwrap();
    timeout(TEST_TIMEOUT, server.read_exact(&mut echo_ack))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo_ack, [command::IAC, command::DONT, option::ECHO]);
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::RemoteEcho { enabled: false }
    ));

    server
        .write_all(&[command::IAC, command::DO, option::ECHO])
        .await
        .unwrap();
    timeout(TEST_TIMEOUT, server.read_exact(&mut echo_ack))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo_ack, [command::IAC, command::WILL, option::ECHO]);
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::LocalEcho { enabled: true }
    ));

    manager.input(&session_id, b"whoami\r").unwrap();
    let mut manual = [0_u8; 8];
    timeout(TEST_TIMEOUT, server.read_exact(&mut manual))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&manual, b"whoami\r\n");

    manager.close(&session_id).unwrap();
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Requested
        }
    ));
    wait_for_cleanup(&manager, &session_id).await;
    let mut eof = [0_u8; 1];
    assert_eq!(
        timeout(TEST_TIMEOUT, server.read(&mut eof))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_input_permanently_cancels_auto_login_and_cancel_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let manager = TelnetRuntimeManager::new();
    let config = TelnetRuntimeConfig::new(address.ip().to_string(), address.port(), 80, 24)
        .unwrap()
        .with_username("auto-user")
        .unwrap()
        .with_password("auto-password")
        .unwrap()
        .with_startup_command("auto-start")
        .unwrap();
    let mut runtime = manager.start(config).unwrap();
    let session_id = runtime.session_id().clone();
    let (mut server, _) = listener.accept().await.unwrap();
    expect_connect(&mut runtime).await;

    manager.input(&session_id, b"manual\r").unwrap();
    let mut manual = [0_u8; 8];
    timeout(TEST_TIMEOUT, server.read_exact(&mut manual))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&manual, b"manual\r\n");
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::AutoLoginCancelled
    ));

    for prompt in [b"Username: ".as_slice(), b"\r\nPassword: ", b"\r\nrouter# "] {
        server.write_all(prompt).await.unwrap();
        expect_data(&mut runtime, prompt).await;
    }
    assert_no_socket_data(&mut server).await;

    manager.cancel(&session_id).unwrap();
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Cancelled
        }
    ));
    wait_for_cleanup(&manager, &session_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_login_timeout_is_published_once_without_sending_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let manager = TelnetRuntimeManager::new();
    let config = TelnetRuntimeConfig::new(address.ip().to_string(), address.port(), 80, 24)
        .unwrap()
        .with_username("must-not-send")
        .unwrap()
        .with_auto_login_timeout(Duration::from_millis(1));
    let mut runtime = manager.start(config).unwrap();
    let session_id = runtime.session_id().clone();
    let (mut server, _) = listener.accept().await.unwrap();
    expect_connect(&mut runtime).await;
    sleep(Duration::from_millis(10)).await;

    server.write_all(b"Username: ").await.unwrap();
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::AutoLoginTimedOut
    ));
    expect_data(&mut runtime, b"Username: ").await;
    assert_no_socket_data(&mut server).await;

    server.write_all(b"Username: ").await.unwrap();
    expect_data(&mut runtime, b"Username: ").await;
    assert_no_socket_data(&mut server).await;
    manager.close(&session_id).unwrap();
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Requested
        }
    ));
    wait_for_cleanup(&manager, &session_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_failure_is_terminal_and_cleans_registry() {
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    drop(unavailable);

    let manager = TelnetRuntimeManager::new();
    let config = TelnetRuntimeConfig::new(
        unavailable_address.ip().to_string(),
        unavailable_address.port(),
        80,
        24,
    )
    .unwrap();
    let mut failed = manager.start(config).unwrap();
    let failed_id = failed.session_id().clone();
    assert!(matches!(
        next_event(&mut failed).await,
        TelnetRuntimeEvent::Connecting
    ));
    assert!(matches!(
        next_event(&mut failed).await,
        TelnetRuntimeEvent::Error(TelnetRuntimeError::ConnectionFailed { .. })
    ));
    assert!(matches!(
        next_event(&mut failed).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Error
        }
    ));
    wait_for_cleanup(&manager, &failed_id).await;
}

#[tokio::test]
async fn in_flight_connect_is_cancellable_and_command_queue_is_bounded() {
    let manager = TelnetRuntimeManager::new();
    // No await occurs between start, filling the bounded queue, and cancel,
    // so this current-thread runtime cannot drain commands or evade the bound.
    let config = TelnetRuntimeConfig::new("203.0.113.1", 65000, 80, 24).unwrap();
    let mut cancelled = manager.start(config).unwrap();
    let cancelled_id = cancelled.session_id().clone();
    for _ in 0..COMMAND_CHANNEL_CAPACITY {
        manager.input(&cancelled_id, b"x").unwrap();
    }
    assert_eq!(
        manager.input(&cancelled_id, b"overflow"),
        Err(TelnetRuntimeError::CommandQueueFull {
            capacity: COMMAND_CHANNEL_CAPACITY
        })
    );
    manager.cancel(&cancelled_id).unwrap();
    assert!(matches!(
        next_event(&mut cancelled).await,
        TelnetRuntimeEvent::Connecting
    ));
    assert!(matches!(
        next_event(&mut cancelled).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Cancelled
        }
    ));
    wait_for_cleanup(&manager, &cancelled_id).await;
    assert_eq!(manager.session_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_dns_sessions_have_unique_ids_and_independent_cleanup() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let manager = TelnetRuntimeManager::new();
    let mut first = manager
        .start(TelnetRuntimeConfig::new("localhost", port, 80, 24).unwrap())
        .unwrap();
    let mut second = manager
        .start(TelnetRuntimeConfig::new("localhost", port, 81, 25).unwrap())
        .unwrap();
    let first_id = first.session_id().clone();
    let second_id = second.session_id().clone();
    assert_ne!(first_id, second_id);
    assert_eq!(manager.session_count(), 2);

    let (peer_a, peer_b) = tokio::join!(listener.accept(), listener.accept());
    let (mut peer_a, _) = peer_a.unwrap();
    let (mut peer_b, _) = peer_b.unwrap();
    expect_connect(&mut first).await;
    expect_connect(&mut second).await;

    peer_a.write_all(b"one").await.unwrap();
    peer_b.write_all(b"two").await.unwrap();
    let first_data = next_event(&mut first).await;
    let second_data = next_event(&mut second).await;
    let received = match (first_data, second_data) {
        (TelnetRuntimeEvent::Data(first), TelnetRuntimeEvent::Data(second)) => {
            vec![first.into_vec(), second.into_vec()]
        }
        other => panic!("unexpected concurrent events: {other:?}"),
    };
    assert!(received.contains(&b"one".to_vec()));
    assert!(received.contains(&b"two".to_vec()));

    manager.close(&first_id).unwrap();
    manager.close(&second_id).unwrap();
    assert!(matches!(
        next_event(&mut first).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Requested
        }
    ));
    assert!(matches!(
        next_event(&mut second).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Requested
        }
    ));
    wait_for_cleanup(&manager, &first_id).await;
    wait_for_cleanup(&manager, &second_id).await;
    assert_eq!(manager.session_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_loopback_is_supported_when_available() {
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let manager = TelnetRuntimeManager::new();
    let mut runtime = manager
        .start(TelnetRuntimeConfig::new("::1", port, 80, 24).unwrap())
        .unwrap();
    let session_id = runtime.session_id().clone();
    let (_server, _) = listener.accept().await.unwrap();
    expect_connect(&mut runtime).await;
    manager.close(&session_id).unwrap();
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Requested
        }
    ));
    wait_for_cleanup(&manager, &session_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gb18030_tcp_output_auto_login_and_renderer_input_are_symmetric() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let manager = TelnetRuntimeManager::new();
    let charset = TelnetCharset::parse_label("zh_CN.GBK");
    let config = TelnetRuntimeConfig::new(address.ip().to_string(), address.port(), 80, 24)
        .unwrap()
        .with_charset(charset)
        .with_username("管理员")
        .unwrap()
        .with_password("秘密")
        .unwrap()
        .with_startup_command("查看状态")
        .unwrap();
    let mut runtime = manager.start(config).unwrap();
    let session_id = runtime.session_id().clone();
    let (mut server, _) = listener.accept().await.unwrap();
    expect_connect(&mut runtime).await;

    let username_prompt = encoding_rs::GB18030.encode("用户名: ").0.into_owned();
    server.write_all(&username_prompt[..1]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(80), runtime.recv())
            .await
            .is_err(),
        "a split GB18030 character must not emit partial UTF-8"
    );
    server.write_all(&username_prompt[1..]).await.unwrap();
    let expected_username = encoding_rs::GB18030.encode("管理员\r\n").0.into_owned();
    let mut received_username = vec![0_u8; expected_username.len()];
    timeout(TEST_TIMEOUT, server.read_exact(&mut received_username))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received_username, expected_username);
    expect_data(&mut runtime, "用户名: ".as_bytes()).await;

    let password_prompt = encoding_rs::GB18030.encode("密码: ").0.into_owned();
    server.write_all(&password_prompt).await.unwrap();
    let expected_password = encoding_rs::GB18030.encode("秘密\r\n").0.into_owned();
    let mut received_password = vec![0_u8; expected_password.len()];
    timeout(TEST_TIMEOUT, server.read_exact(&mut received_password))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received_password, expected_password);
    expect_data(&mut runtime, "密码: ".as_bytes()).await;

    let shell_prompt = encoding_rs::GB18030.encode("\r\n设备# ").0.into_owned();
    server.write_all(&shell_prompt).await.unwrap();
    let expected_startup = encoding_rs::GB18030.encode("查看状态\r\n").0.into_owned();
    let mut received_startup = vec![0_u8; expected_startup.len()];
    timeout(TEST_TIMEOUT, server.read_exact(&mut received_startup))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received_startup, expected_startup);
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::AutoLoginCompleted
    ));
    expect_data(&mut runtime, "\r\n设备# ".as_bytes()).await;

    manager.input(&session_id, "查看版本\r".as_bytes()).unwrap();
    let expected_input = encoding_rs::GB18030.encode("查看版本\r\n").0.into_owned();
    let mut received_input = vec![0_u8; expected_input.len()];
    timeout(TEST_TIMEOUT, server.read_exact(&mut received_input))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received_input, expected_input);

    manager.close(&session_id).unwrap();
    assert!(matches!(
        next_event(&mut runtime).await,
        TelnetRuntimeEvent::Closed {
            reason: TelnetCloseReason::Requested
        }
    ));
    wait_for_cleanup(&manager, &session_id).await;
}
