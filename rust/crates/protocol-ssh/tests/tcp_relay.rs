//! In-process 6J-A TCP relay: SSH client → russh authority → echo.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rewrite_model::{Destination, Host};
use rewrite_protocol_ssh::{AuthorityOptions, Client, ClientOptions, spawn_authority};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const USER_PRIVATE: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCJATxQ2CZyqkJhvTPFe1yZO//fWnzDm2egKYdZYepm+wAAAJigEL/JoBC/
yQAAAAtzc2gtZWQyNTUxOQAAACCJATxQ2CZyqkJhvTPFe1yZO//fWnzDm2egKYdZYepm+w
AAAEA+sc5BoZ+2Y3aD7XEsKE8KpUp2Ny6KGi1FzyekBZFOGIkBPFDYJnKqQmG9M8V7XJk7
/99afMObZ6Aph1lh6mb7AAAAEHJld3JpdGUtNmphLXVzZXIBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

const USER_PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIkBPFDYJnKqQmG9M8V7XJk7/99afMObZ6Aph1lh6mb7 rewrite-6ja-user";

const WRONG_HOST: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFUL9mPOkdRxCeGwsysi7f09LuLw6KrHBJpZ6Eqx0P7T wrong-host";

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

fn client_options(
    port: u16,
    password: Option<&str>,
    private_key: Option<&str>,
    host_keys: Vec<String>,
) -> ClientOptions {
    ClientOptions {
        server: "127.0.0.1".to_owned(),
        port,
        username: "alice".to_owned(),
        password: password.map(ToOwned::to_owned),
        private_key: private_key.map(ToOwned::to_owned),
        private_key_passphrase: None,
        host_keys,
        host_key_algorithms: Vec::new(),
        bind_interface: String::new(),
        routing_mark: 0,
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

#[tokio::test]
async fn raw_russh_connects_with_password() {
    use std::sync::Arc;

    use russh::client;
    use russh::keys::PublicKey;

    struct AcceptAll;
    impl client::Handler for AcceptAll {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    let (listen, _) = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let mut handle = client::connect(Arc::new(client::Config::default()), listen, AcceptAll)
        .await
        .expect("raw connect");
    assert!(matches!(
        handle
            .authenticate_password("alice", "secret")
            .await
            .expect("auth"),
        russh::client::AuthResult::Success
    ));
}

#[tokio::test]
async fn password_relays_echo_and_reuses_session() {
    let (dest, _echo) = echo_listener().await;
    let (listen, host_key) = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let client = Client::new(client_options(
        listen.port(),
        Some("secret"),
        None,
        vec![host_key],
    ))
    .expect("client");
    exchange(&client, &dest, b"ssh-password").await;
    exchange(&client, &dest, b"ssh-reuse").await;
    client.close().await;
}

#[tokio::test]
async fn publickey_relays_echo() {
    let (dest, _echo) = echo_listener().await;
    let (listen, _) = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: None,
            authorized_keys: vec![USER_PUBLIC.to_owned()],
        },
    )
    .await
    .expect("authority");
    let client = Client::new(client_options(
        listen.port(),
        None,
        Some(USER_PRIVATE),
        Vec::new(),
    ))
    .expect("client");
    exchange(&client, &dest, b"ssh-pubkey").await;
    client.close().await;
}

#[tokio::test]
async fn host_key_mismatch_is_rejected() {
    let (listen, _) = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let client = Client::new(client_options(
        listen.port(),
        Some("secret"),
        None,
        vec![WRONG_HOST.to_owned()],
    ))
    .expect("client");
    let dest = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: 9,
    };
    let Err(error) = client.open_tcp(&dest).await else {
        panic!("host key mismatch was accepted")
    };
    assert!(
        error.to_string().to_ascii_lowercase().contains("key")
            || error.to_string().to_ascii_lowercase().contains("host")
            || error.to_string().to_ascii_lowercase().contains("protocol"),
        "{error}"
    );
}

#[tokio::test]
async fn dest_refused_does_not_drop_session() {
    let (dest, _echo) = echo_listener().await;
    let (listen, _) = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let client = Client::new(client_options(
        listen.port(),
        Some("secret"),
        None,
        Vec::new(),
    ))
    .expect("client");
    let refused = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: 1,
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), client.open_tcp(&refused)).await;
    exchange(&client, &dest, b"after-refused").await;
    client.close().await;
}

#[tokio::test]
async fn concurrent_direct_tcpip_streams() {
    let (dest, _echo) = echo_listener().await;
    let (listen, _) = spawn_authority(
        "127.0.0.1:0".parse().expect("listen"),
        AuthorityOptions {
            username: "alice".to_owned(),
            password: Some("secret".to_owned()),
            authorized_keys: Vec::new(),
        },
    )
    .await
    .expect("authority");
    let client = std::sync::Arc::new(
        Client::new(client_options(
            listen.port(),
            Some("secret"),
            None,
            Vec::new(),
        ))
        .expect("client"),
    );
    let mut tasks = Vec::new();
    for index in 0..4 {
        let client = std::sync::Arc::clone(&client);
        let dest = dest.clone();
        tasks.push(tokio::spawn(async move {
            exchange(&client, &dest, format!("c{index}").as_bytes()).await;
        }));
    }
    for task in tasks {
        task.await.expect("join");
    }
    client.close().await;
}
