//! Live Accept: server auth + TCP echo via protocol client.

use std::sync::Arc;
use std::time::Duration;

use rewrite_model::{Destination, Host};
use rewrite_protocol_hysteria2::{
    Client, ClientOptions, ServerAuthOptions, ServerEndpointOptions, TlsOptions,
    accept_tcp_request, authenticate_incoming, bind_server_endpoint, password_user_table,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn self_signed() -> (String, String) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["dot.phase4.test".to_owned()]).expect("cert");
    (certified.cert.pem(), certified.key_pair.serialize_pem())
}

#[tokio::test]
async fn server_auth_and_tcp_round_trip() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (cert, key) = self_signed();
    let endpoint = bind_server_endpoint(&ServerEndpointOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        certificate_pem: cert,
        private_key_pem: key,
        alpn: vec!["h3".to_owned()],
        ..ServerEndpointOptions::default()
    })
    .expect("bind");
    let addr = endpoint.local_addr().unwrap();
    let users = Arc::new(password_user_table([("alice", "secret")]));

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let connection = incoming.await.expect("handshake");
        let authenticated =
            authenticate_incoming(connection.clone(), &users, ServerAuthOptions::default())
                .await
                .expect("auth");
        assert_eq!(authenticated.result.username, "alice");
        // Retain h3 guard for the session — Drop would close Quinn with H3_NO_ERROR.
        let _h3 = authenticated.h3_guard;
        let (send, recv) = connection.accept_bi().await.expect("bi");
        let (destination, mut stream) = accept_tcp_request(send, recv).await.expect("tcp");
        assert_eq!(destination.port, 9);
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hello");
        stream.write_all(b"hello").await.expect("write");
        stream.flush().await.expect("flush");
        let _ = done_rx.await;
    });

    let client = Client::new(ClientOptions {
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        password: "secret".to_owned(),
        tls: TlsOptions {
            server_name: "dot.phase4.test".to_owned(),
            skip_certificate_verification: true,
            alpn: vec!["h3".to_owned()],
            custom_roots: Vec::new(),
        },
        disable_reuse: true,
        handshake_timeout: Duration::from_secs(5),
        ..ClientOptions::default()
    })
    .expect("client");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(8),
        client.open_tcp(&Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 9,
        }),
    )
    .await
    .expect("open timeout")
    .expect("open tcp");
    stream.write_all(b"hello").await.expect("client write");
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"hello");
    let _ = done_tx.send(());
    server.await.expect("server");
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (cert, key) = self_signed();
    let endpoint = bind_server_endpoint(&ServerEndpointOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        certificate_pem: cert,
        private_key_pem: key,
        alpn: vec!["h3".to_owned()],
        ..ServerEndpointOptions::default()
    })
    .expect("bind");
    let addr = endpoint.local_addr().unwrap();
    let users = Arc::new(password_user_table([("alice", "secret")]));

    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let connection = incoming.await.expect("handshake");
        let err = authenticate_incoming(connection, &users, ServerAuthOptions::default()).await;
        assert!(err.is_err(), "wrong password must fail");
    });

    let client = Client::new(ClientOptions {
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        password: "wrong".to_owned(),
        tls: TlsOptions {
            server_name: "dot.phase4.test".to_owned(),
            skip_certificate_verification: true,
            alpn: vec!["h3".to_owned()],
            custom_roots: Vec::new(),
        },
        disable_reuse: true,
        handshake_timeout: Duration::from_secs(5),
        ..ClientOptions::default()
    })
    .expect("client");
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        client.open_tcp(&Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 9,
        }),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_)) | Err(_)),
        "client must fail auth"
    );
    let _ = server.await;
}
