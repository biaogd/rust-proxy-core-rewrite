//! 6J-B lifecycle: host-key-algorithms, transport keepalive, passphrase file,
//! and reconnect after the authority restarts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use rewrite_model::{Destination, Host};
use rewrite_protocol_ssh::{AuthorityOptions, Client, ClientOptions, spawn_authority};
use russh::keys::ssh_key::{LineEnding, rand_core::OsRng};
use russh::keys::{Algorithm, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn echo_listener() -> (Destination, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (
        Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: addr.port(),
        },
        task,
    )
}

fn client_options(port: u16) -> ClientOptions {
    ClientOptions {
        server: "127.0.0.1".to_owned(),
        port,
        username: "alice".to_owned(),
        password: Some("secret".to_owned()),
        private_key: None,
        private_key_passphrase: None,
        host_keys: Vec::new(),
        host_key_algorithms: Vec::new(),
        bind_interface: String::new(),
        routing_mark: 0,
        keep_alive_idle: 1,
        keep_alive_interval: 1,
        disable_keep_alive: false,
    }
}

async fn exchange(client: &Client, dest: &Destination, payload: &[u8]) {
    let mut stream = match client.open_tcp(dest).await {
        Ok(stream) => stream,
        Err(error) => panic!("open tcp: {error:?}"),
    };
    stream.write_all(payload).await.expect("write");
    let mut got = vec![0_u8; payload.len()];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload);
}

fn encrypted_user_key() -> (String, String, String) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("random key");
    let public = key.public_key().to_openssh().expect("public openssh");
    let encrypted = key.encrypt(&mut OsRng, "phrase").expect("encrypt");
    let pem = encrypted.to_openssh(LineEnding::LF).expect("encrypted pem");
    (public, pem.to_string(), "phrase".to_owned())
}

#[tokio::test]
async fn host_key_algorithms_ed25519_relays() {
    let (dest, _echo) = echo_listener().await;
    let authority = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let mut options = client_options(authority.listen.port());
    options.host_key_algorithms = vec!["ssh-ed25519".to_owned()];
    options.host_keys = vec![authority.host_key.clone()];
    let client = Client::new(options).expect("client");
    exchange(&client, &dest, b"algs-ed25519").await;
    client.close().await;
}

#[tokio::test]
async fn host_key_algorithms_rsa_rejected_against_ed25519_authority() {
    let authority = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let mut options = client_options(authority.listen.port());
    options.host_key_algorithms = vec!["rsa-sha2-256".to_owned()];
    let client = Client::new(options).expect("client");
    let dest = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: 9,
    };
    let Err(error) = client.open_tcp(&dest).await else {
        panic!("rsa-only host-key-algorithms was accepted by an ed25519 authority")
    };
    let text = error.to_string().to_ascii_lowercase();
    assert!(
        text.contains("handshake")
            || text.contains("protocol")
            || text.contains("kex")
            || text.contains("key"),
        "{error}"
    );
}

#[tokio::test]
async fn passphrase_file_publickey_relays() {
    let (dest, _echo) = echo_listener().await;
    let (public, pem, phrase) = encrypted_user_key();
    let path = std::env::temp_dir().join(format!(
        "rewrite-6jb-ssh-{}-{}.pem",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::write(&path, pem.as_bytes()).expect("write key");
    let authority = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: None,
            authorized_keys: vec![public],
        },
    )
    .await
    .expect("authority");
    let client = Client::new(ClientOptions {
        server: "127.0.0.1".to_owned(),
        port: authority.listen.port(),
        username: "alice".to_owned(),
        password: None,
        private_key: Some(path.to_string_lossy().into_owned()),
        private_key_passphrase: Some(phrase),
        host_keys: Vec::new(),
        host_key_algorithms: vec!["ssh-ed25519".to_owned()],
        bind_interface: String::new(),
        routing_mark: 0,
        keep_alive_idle: 1,
        keep_alive_interval: 1,
        disable_keep_alive: false,
    })
    .expect("client");
    exchange(&client, &dest, b"passphrase-file").await;
    client.close().await;
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn authority_restart_reconnects_without_close() {
    let (dest, _echo) = echo_listener().await;
    let first = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let listen = first.listen;
    let client = Client::new(client_options(listen.port())).expect("client");
    exchange(&client, &dest, b"before-restart").await;
    first.shutdown();
    drop(first);

    let dest_fail = tokio::time::timeout(Duration::from_secs(3), client.open_tcp(&dest)).await;
    assert!(
        matches!(dest_fail, Ok(Err(_)) | Err(_)),
        "dead authority still accepted a dial"
    );

    let mut restarted = None;
    for _ in 0..20 {
        match spawn_authority(
            listen,
            AuthorityOptions {
                username: "alice".to_owned(),
                password: Some("secret".to_owned()),
                authorized_keys: Vec::new(),
            },
        )
        .await
        {
            Ok(authority) => {
                restarted = Some(authority);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let _restarted = restarted.expect("rebind authority");
    exchange(&client, &dest, b"after-restart").await;

    let refused = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: 1,
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), client.open_tcp(&refused)).await;
    exchange(&client, &dest, b"after-refused").await;
    client.close().await;
}

#[tokio::test]
async fn keepalive_socket_still_reuses_session() {
    let (dest, _echo) = echo_listener().await;
    let authority = spawn_authority(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let client = Client::new(client_options(authority.listen.port())).expect("client");
    exchange(&client, &dest, b"keep-1").await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    exchange(&client, &dest, b"keep-2").await;
    client.close().await;
}
