use rewrite_model::{Destination, Host};
use rewrite_protocol_hysteria2::{Client, ClientOptions, TlsOptions};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn probe_against_env_authority() {
    let Ok(port) = std::env::var("AUTH_PORT") else {
        return;
    };
    let password = std::env::var("PASSWORD").unwrap();
    let sni = std::env::var("SNI").unwrap();
    let echo: u16 = std::env::var("ECHO_PORT").unwrap().parse().unwrap();
    eprintln!("connecting to auth {port} echo {echo}");
    let client = Client::new(ClientOptions {
        server: "127.0.0.1".into(),
        port: port.parse().unwrap(),
        password,
        tls: TlsOptions {
            server_name: sni,
            skip_certificate_verification: true,
            alpn: vec!["h3".into()],
            custom_roots: vec![],
        },
        disable_reuse: true,
        ..ClientOptions::default()
    })
    .expect("client options");
    let dest = Destination {
        host: Host::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        port: echo,
    };
    let open = tokio::time::timeout(Duration::from_secs(8), client.open_tcp(&dest)).await;
    let mut stream = match open {
        Ok(Ok(stream)) => {
            eprintln!("open_tcp ok");
            stream
        }
        Ok(Err(error)) => panic!("open_tcp failed: {error:#}"),
        Err(_) => panic!("open_tcp timed out"),
    };
    stream.write_all(b"ping").await.expect("write");
    let mut buf = [0_u8; 4];
    stream.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"ping");
    eprintln!("probe ok");
}
