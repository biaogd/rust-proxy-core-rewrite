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

#[tokio::test]
async fn split_association_survives_tiny_buffer_bidi_pressure() {
    use std::time::Duration;

    use rewrite_protocol_snell::{SnellUdpReceiver, SnellUdpSender};
    use socket2::{Domain, Protocol, Socket, Type};

    let echo = spawn_udp_echo().await;
    let authority = spawn_authority(AuthorityOptions {
        listen: "127.0.0.1:0".parse().expect("listen"),
        psk: b"bidi-psk".to_vec(),
        version: 3,
        obfs: None,
    })
    .await
    .expect("authority");

    // Tiny socket buffers force both TCP directions to apply backpressure so
    // sequential send-then-recv deadlocks; split halves must progress together.
    let stream = {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("socket");
        let _ = socket.set_send_buffer_size(2_048);
        let _ = socket.set_recv_buffer_size(2_048);
        socket
            .connect(&authority.local_addr.into())
            .expect("connect");
        socket.set_nonblocking(true).expect("nonblocking");
        let std_stream: std::net::TcpStream = socket.into();
        tokio::net::TcpStream::from_std(std_stream).expect("tokio stream")
    };

    let association = associate_udp(
        stream,
        &ClientOptions {
            psk: b"bidi-psk".to_vec(),
            version: 3,
        },
    )
    .await
    .expect("associate");
    let (mut sender, mut receiver): (SnellUdpSender<_>, SnellUdpReceiver<_>) =
        association.into_split();

    // Exceed the authority response queue (8) and the runtime outbound queue
    // (32) so concurrent progress is required under real backpressure.
    const COUNT: usize = 128;
    let payload = vec![0x5a_u8; 512];
    let dest = echo.destination.clone();

    let send_task = tokio::spawn(async move {
        for _ in 0..COUNT {
            sender.send(&dest, &payload).await.expect("send");
        }
    });
    let recv_task = tokio::spawn(async move {
        for _ in 0..COUNT {
            let (_, got) = receiver.recv().await.expect("recv");
            assert_eq!(got.len(), 512);
            assert!(got.iter().all(|byte| *byte == 0x5a));
        }
    });

    tokio::time::timeout(Duration::from_secs(20), async {
        send_task.await.expect("send join");
        recv_task.await.expect("recv join");
    })
    .await
    .expect("bidi pressure must not deadlock");
}
