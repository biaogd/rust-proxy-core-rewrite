use rewrite_model::{Destination, Host};
use rewrite_protocol_snell::{AuthorityOptions, ClientOptions, associate_udp, spawn_authority};
use tokio::net::UdpSocket;

#[tokio::test]
async fn v3_udp_ipv4_echo_and_second_packet() {
    let echo = spawn_udp_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"phase7e-psk".to_vec(),
        version: 3,
        obfs: None,
    })
    .await
    .expect("authority");
    let mut association = associate_udp(
        tokio::net::TcpStream::connect(authority.local_addr)
            .await
            .expect("dial"),
        &ClientOptions {
            psk: b"phase7e-psk".to_vec(),
            version: 3,
        },
    )
    .await
    .expect("associate");
    for payload in [b"snell-udp" as &[u8], b"second"] {
        association
            .send(&echo.destination, payload)
            .await
            .expect("send");
        let (from, got) = association.recv().await.expect("recv");
        assert_eq!(got, payload);
        assert_eq!(from.port, echo.destination.port);
    }
}

#[tokio::test]
async fn v3_udp_domain_echo() {
    let echo = spawn_udp_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"password".to_vec(),
        version: 3,
        obfs: None,
    })
    .await
    .expect("authority");
    let mut association = associate_udp(
        tokio::net::TcpStream::connect(authority.local_addr)
            .await
            .expect("dial"),
        &ClientOptions {
            psk: b"password".to_vec(),
            version: 3,
        },
    )
    .await
    .expect("associate");
    let dest = Destination {
        host: Host::Domain("localhost".to_owned()),
        port: echo.destination.port,
    };
    association.send(&dest, b"domain-udp").await.expect("send");
    let (_, got) = association.recv().await.expect("recv");
    assert_eq!(got, b"domain-udp");
}

#[tokio::test]
async fn v1_udp_is_rejected() {
    let (client, _server) = tokio::io::duplex(64);
    let Err(error) = associate_udp(
        client,
        &ClientOptions {
            psk: b"password".to_vec(),
            version: 1,
        },
    )
    .await
    else {
        panic!("v1 UDP should be rejected");
    };
    assert!(error.to_string().contains("does not support UDP"));
}

#[tokio::test]
async fn oversized_udp_payload_is_rejected() {
    let echo = spawn_udp_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"password".to_vec(),
        version: 3,
        obfs: None,
    })
    .await
    .expect("authority");
    let mut association = associate_udp(
        tokio::net::TcpStream::connect(authority.local_addr)
            .await
            .expect("dial"),
        &ClientOptions {
            psk: b"password".to_vec(),
            version: 3,
        },
    )
    .await
    .expect("associate");
    let huge = vec![0_u8; 0x4000];
    let error = association
        .send(&echo.destination, &huge)
        .await
        .expect_err("oversize");
    assert!(error.to_string().contains("too large"));
}

struct UdpEcho {
    destination: Destination,
}

async fn spawn_udp_echo() -> UdpEcho {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("echo bind");
    let local = socket.local_addr().expect("echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_536];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            if socket.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    UdpEcho {
        destination: Destination {
            host: Host::Ip(local.ip()),
            port: local.port(),
        },
    }
}
