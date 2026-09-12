use std::time::Duration;

use rewrite_model::{Destination, Host};
use rewrite_protocol_snell::{
    AuthorityObfs, AuthorityOptions, ClientOptions, DEFAULT_VERSION, connect_tcp, spawn_authority,
};
use rewrite_transport::{HttpObfsClient, TlsObfsClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn v1_password_echo_and_large_payload() {
    relay_echo(1, b"password", b"snell-v1").await;
    relay_echo(1, b"password", &bytes_range(256 * 512)).await;
}

#[tokio::test]
async fn omitted_version_defaults_to_v1() {
    let echo = spawn_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"password".to_vec(),
        version: 0,
        obfs: None,
    })
    .await
    .expect("authority");
    let mut stream = connect_tcp(
        tokio::net::TcpStream::connect(authority.local_addr)
            .await
            .expect("dial"),
        &echo.destination,
        &ClientOptions {
            psk: b"password".to_vec(),
            version: DEFAULT_VERSION,
        },
    )
    .await
    .expect("client");
    stream.write_all(b"default-v1").await.expect("write");
    let mut got = vec![0_u8; 10];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(got, b"default-v1");
}

#[tokio::test]
async fn v3_aes_gcm_echo() {
    relay_echo(3, b"phase7e-psk", b"snell-v3").await;
}

#[tokio::test]
async fn http_obfs_echo() {
    let echo = spawn_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"password".to_vec(),
        version: 1,
        obfs: Some(AuthorityObfs::Http),
    })
    .await
    .expect("authority");
    let raw = tokio::net::TcpStream::connect(authority.local_addr)
        .await
        .expect("dial");
    let mut stream = connect_tcp(
        HttpObfsClient::new(raw, "bing.com".to_owned(), authority.local_addr.port()),
        &echo.destination,
        &ClientOptions {
            psk: b"password".to_vec(),
            version: 1,
        },
    )
    .await
    .expect("client");
    stream.write_all(b"snell-http").await.expect("write");
    let mut got = vec![0_u8; 10];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(got, b"snell-http");
}

#[tokio::test]
async fn tls_obfs_echo() {
    let echo = spawn_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"phase7e-psk".to_vec(),
        version: 3,
        obfs: Some(AuthorityObfs::Tls),
    })
    .await
    .expect("authority");
    let raw = tokio::net::TcpStream::connect(authority.local_addr)
        .await
        .expect("dial");
    let mut stream = connect_tcp(
        TlsObfsClient::new(raw, "bing.com".to_owned()),
        &echo.destination,
        &ClientOptions {
            psk: b"phase7e-psk".to_vec(),
            version: 3,
        },
    )
    .await
    .expect("client");
    stream.write_all(b"snell-tls").await.expect("write");
    let mut got = vec![0_u8; 9];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(got, b"snell-tls");
}

#[tokio::test]
async fn dest_refused_does_not_panic() {
    let unused = unused_tcp_port().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"password".to_vec(),
        version: 1,
        obfs: None,
    })
    .await
    .expect("authority");
    let mut stream = connect_tcp(
        tokio::net::TcpStream::connect(authority.local_addr)
            .await
            .expect("dial"),
        &Destination {
            host: Host::Ip("127.0.0.1".parse().expect("ip")),
            port: unused,
        },
        &ClientOptions {
            psk: b"password".to_vec(),
            version: 1,
        },
    )
    .await
    .expect("client header");
    stream
        .write_all(b"should-fail")
        .await
        .expect("write header path");
    let mut buf = [0_u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await;
    assert!(
        matches!(result, Ok(Err(_)) | Err(_)),
        "refused dest should not return payload"
    );
}

#[tokio::test]
async fn concurrent_sessions_stay_isolated() {
    let echo = spawn_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"password".to_vec(),
        version: 1,
        obfs: None,
    })
    .await
    .expect("authority");
    let mut joins = Vec::new();
    for index in 0..4 {
        let dest = echo.destination.clone();
        let server = authority.local_addr;
        joins.push(tokio::spawn(async move {
            let payload = format!("c{index}").into_bytes();
            let mut stream = connect_tcp(
                tokio::net::TcpStream::connect(server).await.expect("dial"),
                &dest,
                &ClientOptions {
                    psk: b"password".to_vec(),
                    version: 1,
                },
            )
            .await
            .expect("client");
            stream.write_all(&payload).await.expect("write");
            let mut got = vec![0_u8; payload.len()];
            stream.read_exact(&mut got).await.expect("read");
            assert_eq!(got, payload);
        }));
    }
    for join in joins {
        join.await.expect("session");
    }
}

async fn relay_echo(version: u8, psk: &[u8], payload: &[u8]) {
    let echo = spawn_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: psk.to_vec(),
        version,
        obfs: None,
    })
    .await
    .expect("authority");
    let mut stream = connect_tcp(
        tokio::net::TcpStream::connect(authority.local_addr)
            .await
            .expect("dial"),
        &echo.destination,
        &ClientOptions {
            psk: psk.to_vec(),
            version,
        },
    )
    .await
    .expect("client");
    stream.write_all(payload).await.expect("write");
    let mut got = vec![0_u8; payload.len()];
    stream.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload);
}

struct EchoServer {
    destination: Destination,
}

async fn spawn_echo() -> EchoServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let local = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 65_536];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    EchoServer {
        destination: Destination {
            host: Host::Ip(local.ip()),
            port: local.port(),
        },
    }
}

async fn unused_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("unused");
    let port = listener.local_addr().expect("port").port();
    drop(listener);
    port
}

fn bytes_range(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 256).unwrap_or(0))
        .collect()
}
