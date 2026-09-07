use super::*;
use std::io::BufRead;
use std::process::{Child, Command, Stdio};

struct Authority(Child);
impl Drop for Authority {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn authority(script: &str) -> (Authority, String, String) {
    let binary = std::env::var("RESTLS_AUTHORITY")
        .expect("build compat/helpers/restls_authority and set RESTLS_AUTHORITY");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut child = Command::new(binary)
        .arg(root.join("compat/fixtures/phase4/phase4e2-server.pem"))
        .arg(root.join("compat/fixtures/phase4/phase4e2-server-key.pem"))
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("oracle spawn");
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut line)
        .expect("ready");
    let mut ports = line.split_whitespace();
    let first = ports.next().expect("Restls address").to_owned();
    let second = ports.next().expect("TLS address").to_owned();
    (Authority(child), first, second)
}

async fn connect(address: &str, password: &str, script: &str) -> io::Result<BoxedStream> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../compat/fixtures/phase4/phase4e2-root.pem");
    let roots = [std::fs::read_to_string(root)?];
    let tcp = tokio::net::TcpStream::connect(address).await?;
    connect_restls(
        Box::new(tcp),
        RestlsConnectOptions {
            tls: ClientTlsOptions {
                server_name: "dot.phase4.test",
                verification_name: None,
                skip_certificate_verification: false,
                fingerprint: None,
                certificate: None,
                private_key: None,
                custom_roots: &roots,
                ech_config: None,
                alpn_protocols: &[],
                tls12_only: false,
                tls13_only: true,
            },
            password,
            version_hint: "tls13",
            script,
            client_fingerprint: Some("chrome"),
        },
        None,
    )
    .await
}

#[tokio::test]
#[ignore = "requires RESTLS_AUTHORITY Go oracle binary"]
async fn restls_go_oracle() {
    for script in ["", "200<1,0<2,300~20,400?30,600", "100,200,300"] {
        let (_authority, address, tls_address) = authority(script);
        let mut stream = connect(&address, "restls-test", script)
            .await
            .expect("Restls handshake");
        for size in [1, 32, 4096, 200_000] {
            let payload: Vec<u8> = (0..size).map(|n| u8::try_from(n % 251).unwrap()).collect();
            let (mut read, mut write) = tokio::io::split(&mut stream);
            let mut got = vec![0; size];
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::try_join!(write.write_all(&payload), read.read_exact(&mut got))
            })
            .await
            .expect("relay deadline")
            .expect("echo");
            assert_eq!(got, payload);
        }
        drop(stream);
        assert!(connect(&address, "wrong-password", script).await.is_err());
        assert!(connect(&tls_address, "restls-test", script).await.is_err());
    }
}

#[test]
fn restls_script_rejects_invalid() {
    for script in [
        "x", "32768", "1<255", "1~32768", "20<1oops", "10~", "32767~2",
    ] {
        assert!(codec::parse_script(script).is_err(), "{script}");
    }
    for script in ["", " , ", "0", "250?100<1,350~100<1", "2<0"] {
        assert!(codec::parse_script(script).is_ok());
    }
}
