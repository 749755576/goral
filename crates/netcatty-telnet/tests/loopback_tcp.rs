use netcatty_telnet::{
    DEFAULT_TERMINAL_TYPE, TelnetConfig, TelnetSession, command, option, suboption,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::test]
async fn loopback_tcp_negotiates_and_preserves_application_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(address));
    let (mut server, _) = accepted.unwrap();
    let client = connected.unwrap();
    let mut session = TelnetSession::new(client, TelnetConfig::default());

    // A raw banner neither activates Telnet nor elicits client control bytes.
    server.write_all(b"ready\r\n").await.unwrap();
    let banner = timeout(IO_TIMEOUT, session.read()).await.unwrap().unwrap();
    assert_eq!(banner.application_data(), b"ready\r\n");
    assert!(!session.codec().is_active());
    assert!(!session.resize(100, 40).await.unwrap());

    // The peer's first IAC activates the protocol. DO NAWS acknowledges the
    // initial WILL NAWS and causes the retained 100x40 size to follow it.
    server
        .write_all(&[command::IAC, command::DO, option::NAWS])
        .await
        .unwrap();
    let negotiation = timeout(IO_TIMEOUT, session.read()).await.unwrap().unwrap();
    assert!(negotiation.application_data().is_empty());
    assert!(session.codec().is_active());

    let mut initial_reply = [0_u8; 18];
    timeout(IO_TIMEOUT, server.read_exact(&mut initial_reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        initial_reply,
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

    // TERMINAL-TYPE SEND receives the stable legacy-compatible default.
    server
        .write_all(&[
            command::IAC,
            command::SB,
            option::TERMINAL_TYPE,
            suboption::SEND,
            command::IAC,
            command::SE,
        ])
        .await
        .unwrap();
    timeout(IO_TIMEOUT, session.read()).await.unwrap().unwrap();
    let terminal_type_length = 4 + DEFAULT_TERMINAL_TYPE.len() + 2;
    let mut terminal_type_reply = vec![0_u8; terminal_type_length];
    timeout(IO_TIMEOUT, server.read_exact(&mut terminal_type_reply))
        .await
        .unwrap()
        .unwrap();
    let mut expected_terminal_type = vec![
        command::IAC,
        command::SB,
        option::TERMINAL_TYPE,
        suboption::IS,
    ];
    expected_terminal_type.extend_from_slice(DEFAULT_TERMINAL_TYPE.as_bytes());
    expected_terminal_type.extend_from_slice(&[command::IAC, command::SE]);
    assert_eq!(terminal_type_reply, expected_terminal_type);

    // Application input applies NVT newline conversion and doubles literal
    // IAC bytes only after activation.
    session.write(&[b'x', b'\n', command::IAC]).await.unwrap();
    let mut encoded_input = [0_u8; 5];
    timeout(IO_TIMEOUT, server.read_exact(&mut encoded_input))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        encoded_input,
        [b'x', b'\r', b'\n', command::IAC, command::IAC]
    );

    // An active resize emits NAWS and escapes a 0xFF size byte.
    assert!(session.resize(255, 41).await.unwrap());
    let mut resize = [0_u8; 10];
    timeout(IO_TIMEOUT, server.read_exact(&mut resize))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resize,
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

    // An escaped data IAC split across real socket reads is reconstructed.
    server.write_all(&[b'a', command::IAC]).await.unwrap();
    let first_half = timeout(IO_TIMEOUT, session.read()).await.unwrap().unwrap();
    assert_eq!(first_half.application_data(), b"a");
    server.write_all(&[command::IAC, b'b']).await.unwrap();
    let second_half = timeout(IO_TIMEOUT, session.read()).await.unwrap().unwrap();
    assert_eq!(second_half.application_data(), &[command::IAC, b'b']);

    session.shutdown().await.unwrap();
    let mut eof_probe = [0_u8; 1];
    assert_eq!(
        timeout(IO_TIMEOUT, server.read(&mut eof_probe))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
