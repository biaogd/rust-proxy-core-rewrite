//! Client UDP association with SIP022 session state.

use std::sync::Mutex;

use rewrite_model::Destination;
use shadowsocks::config::ServerType;
use shadowsocks::context::Context;
use shadowsocks::net::UdpSocket as ShadowUdpSocket;
use shadowsocks::relay::udprelay::ProxySocket;
use shadowsocks::relay::udprelay::proxy_socket::{ProxySocketError, UdpSocketType};

use crate::udp_session::{ClientUdpState, lock_client_state};
use crate::{
    ShadowsocksProtocolError, address_destination, cipher_kind, client_server_config,
    destination_address,
};

/// Connected SIP004/SIP022 UDP client association.
pub struct ShadowsocksUdpAssociation {
    socket: ProxySocket<ShadowUdpSocket>,
    state: Mutex<ClientUdpState>,
}

impl ShadowsocksUdpAssociation {
    /// Wraps a connected UDP socket in the SIP004/SIP022 packet codec.
    ///
    /// AEAD-2022 associations allocate a nonzero client session identifier and
    /// incrementing packet counters. Pre-2022 methods ignore that control block.
    ///
    /// # Errors
    ///
    /// Returns an error when server configuration is invalid.
    pub fn from_connected_socket(
        socket: tokio::net::UdpSocket,
        server: &Destination,
        password: &str,
        cipher: &str,
    ) -> Result<Self, ShadowsocksProtocolError> {
        let method = cipher_kind(cipher)?;
        let server = client_server_config(server, password, cipher)?;
        let socket = ProxySocket::from_socket(
            UdpSocketType::Client,
            Context::new_shared(ServerType::Local),
            &server,
            ShadowUdpSocket::from(socket),
        );
        Ok(Self {
            socket,
            state: Mutex::new(ClientUdpState::new(method.is_aead_2022())),
        })
    }

    /// Sends one encrypted Shadowsocks datagram.
    ///
    /// # Errors
    ///
    /// Returns an authentication, framing or socket error.
    pub async fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), ShadowsocksProtocolError> {
        let control = lock_client_state(&self.state).next_send_control();
        self.socket
            .send_with_ctrl(&destination_address(destination), &control, payload)
            .await
            .map(|_| ())
            .map_err(|error| ShadowsocksProtocolError::Protocol(error.to_string()))
    }

    /// Receives one authenticated Shadowsocks datagram.
    ///
    /// Duplicate, too-old, wrong-session and AEAD-authentication failures are
    /// dropped so a single junk datagram does not tear the association down.
    ///
    /// # Errors
    ///
    /// Returns a socket error when the underlying datagram socket fails.
    pub async fn recv(&self) -> Result<(Destination, Vec<u8>), ShadowsocksProtocolError> {
        loop {
            let mut buffer = vec![0_u8; 65_536];
            match self.socket.recv_with_ctrl(&mut buffer).await {
                Ok((length, address, _, control)) => {
                    if lock_client_state(&self.state)
                        .accept_recv(control.as_ref())
                        .is_err()
                    {
                        continue;
                    }
                    buffer.truncate(length);
                    return Ok((address_destination(address), buffer));
                }
                Err(ProxySocketError::IoError(error)) => {
                    return Err(ShadowsocksProtocolError::Io(error));
                }
                Err(
                    ProxySocketError::ProtocolError(_)
                    | ProxySocketError::ProtocolErrorWithPeer(_, _),
                ) => {}
                Err(error) => {
                    return Err(ShadowsocksProtocolError::Protocol(error.to_string()));
                }
            }
        }
    }
}

/// Returns whether `cipher` is an AEAD-2022 method supported by the core.
#[must_use]
pub fn aead_2022_cipher(cipher: &str) -> bool {
    cipher_kind(cipher).is_ok_and(|method| method.is_aead_2022())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use rewrite_model::{Destination, Host};
    use shadowsocks::config::{ServerConfig, ServerType, ServerUser, ServerUserManager};
    use shadowsocks::context::Context;
    use shadowsocks::crypto::CipherKind;
    use shadowsocks::net::UdpSocket as ShadowUdpSocket;
    use shadowsocks::relay::socks5::Address;
    use shadowsocks::relay::udprelay::ProxySocket;
    use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;

    use super::ShadowsocksUdpAssociation;
    use crate::udp_session::Aead2022ServerSessions;
    use crate::{address_destination, destination_address};

    const KEY_128: &str = "AAECAwQFBgcICQoLDA0ODw==";
    const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const USER_KEY_128: &str = "EBESExQVFhcYGRobHB0eHw==";
    const USER_KEY_256: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn echo_destination() -> Destination {
        Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 9,
        }
    }

    async fn bind_pair() -> (UdpSocket, SocketAddr, UdpSocket, SocketAddr) {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("server bind");
        let server_addr = server.local_addr().expect("server addr");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let client_addr = client.local_addr().expect("client addr");
        client.connect(server_addr).await.expect("client connect");
        (client, client_addr, server, server_addr)
    }

    fn server_config(
        listen: SocketAddr,
        password: &str,
        cipher: &str,
        user_key: Option<&str>,
    ) -> ServerConfig {
        let method = cipher.parse::<CipherKind>().expect("cipher");
        let mut server = ServerConfig::new(listen, password, method).expect("server config");
        if let Some(user_key) = user_key {
            let mut users = ServerUserManager::new();
            users.add_user(ServerUser::with_encoded_key("phase6c-eih", user_key).expect("user"));
            server.set_user_manager(users);
        }
        server
    }

    fn spawn_echo(
        socket: UdpSocket,
        listen: SocketAddr,
        password: &str,
        cipher: &str,
        user_key: Option<&str>,
    ) -> tokio::task::JoinHandle<()> {
        let server = server_config(listen, password, cipher, user_key);
        let proxy = ProxySocket::from_socket(
            UdpSocketType::Server,
            Context::new_shared(ServerType::Server),
            &server,
            ShadowUdpSocket::from(socket),
        );
        tokio::spawn(async move {
            let mut sessions = Aead2022ServerSessions::default();
            let mut buffer = vec![0_u8; 65_536];
            loop {
                let Ok((length, peer, destination, _, control)) =
                    proxy.recv_from_with_ctrl(&mut buffer).await
                else {
                    continue;
                };
                let reply = sessions.prepare_reply(peer, control.as_ref());
                let _ = proxy
                    .send_to_with_ctrl(peer, &destination, &reply, &buffer[..length])
                    .await;
            }
        })
    }

    fn associate(
        socket: UdpSocket,
        server: SocketAddr,
        password: &str,
        cipher: &str,
    ) -> ShadowsocksUdpAssociation {
        ShadowsocksUdpAssociation::from_connected_socket(
            socket,
            &Destination {
                host: Host::Ip(server.ip()),
                port: server.port(),
            },
            password,
            cipher,
        )
        .expect("client association")
    }

    async fn exchange(
        association: &ShadowsocksUdpAssociation,
        payload: &[u8],
    ) -> (Destination, Vec<u8>) {
        let destination = echo_destination();
        association.send(&destination, payload).await.expect("send");
        tokio::time::timeout(Duration::from_secs(2), association.recv())
            .await
            .expect("recv timeout")
            .expect("recv")
    }

    #[tokio::test]
    async fn roundtrips_standard_2022_udp_ciphers() {
        for (cipher, password) in [
            ("2022-blake3-aes-128-gcm", KEY_128),
            ("2022-blake3-aes-256-gcm", KEY_256),
            ("2022-blake3-chacha20-poly1305", KEY_256),
        ] {
            let (client, _, server, server_addr) = bind_pair().await;
            let _echo = spawn_echo(server, server_addr, password, cipher, None);
            let association = associate(client, server_addr, password, cipher);
            let first = b"ss2022-udp-first";
            let (destination, payload) = exchange(&association, first).await;
            assert_eq!(destination, echo_destination(), "{cipher}");
            assert_eq!(payload, first, "{cipher}");
            let second = vec![0xAB; 1400];
            let (_, payload) = exchange(&association, &second).await;
            assert_eq!(payload, second, "{cipher} large");
        }
    }

    #[tokio::test]
    async fn roundtrips_aes_single_hop_eih_udp() {
        for (cipher, server_key, user_key) in [
            ("2022-blake3-aes-128-gcm", KEY_128, USER_KEY_128),
            ("2022-blake3-aes-256-gcm", KEY_256, USER_KEY_256),
        ] {
            let (client, _, server, server_addr) = bind_pair().await;
            let _echo = spawn_echo(server, server_addr, server_key, cipher, Some(user_key));
            let association = associate(
                client,
                server_addr,
                &format!("{server_key}:{user_key}"),
                cipher,
            );
            let (_, payload) = exchange(&association, b"ss2022-eih").await;
            assert_eq!(payload, b"ss2022-eih", "{cipher}");
        }
    }

    #[tokio::test]
    async fn chacha8_udp_roundtrips_at_library_boundary() {
        let cipher = "2022-blake3-chacha8-poly1305";
        let (client, _, server, server_addr) = bind_pair().await;
        let _echo = spawn_echo(server, server_addr, KEY_256, cipher, None);
        let association = associate(client, server_addr, KEY_256, cipher);
        let (_, payload) = exchange(&association, b"chacha8-lib").await;
        assert_eq!(payload, b"chacha8-lib");
    }

    #[tokio::test]
    async fn rejects_wrong_key_tampered_and_truncated_packets() {
        let cipher = "2022-blake3-aes-128-gcm";
        let (client, client_addr, server, server_addr) = bind_pair().await;
        let _echo = spawn_echo(server, server_addr, KEY_128, cipher, None);
        let raw = UdpSocket::bind("127.0.0.1:0").await.expect("raw");
        let association = associate(client, server_addr, KEY_128, cipher);
        let (_, payload) = exchange(&association, b"good").await;
        assert_eq!(payload, b"good");

        raw.send_to(&[0_u8; 16], client_addr)
            .await
            .expect("truncated");
        raw.send_to(&[0x55; 80], client_addr)
            .await
            .expect("tampered");
        let wrong_client = UdpSocket::bind("127.0.0.1:0").await.expect("wrong bind");
        wrong_client
            .connect(server_addr)
            .await
            .expect("wrong connect");
        let wrong = associate(wrong_client, server_addr, USER_KEY_128, cipher);
        let _ = wrong.send(&echo_destination(), b"bad-key").await;
        let (_, payload) = exchange(&association, b"after-junk").await;
        assert_eq!(payload, b"after-junk");
    }

    #[tokio::test]
    async fn drops_replayed_server_datagrams() {
        let cipher = "2022-blake3-aes-128-gcm";
        let (client, client_addr, server, server_addr) = bind_pair().await;
        let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let intercept = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("intercept bind"),
        );
        let intercept_addr = intercept.local_addr().expect("intercept addr");
        let intercept_task = Arc::clone(&intercept);
        let seen_for_server = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_536];
            loop {
                let Ok((length, from)) = intercept_task.recv_from(&mut buffer).await else {
                    break;
                };
                if from == server_addr {
                    seen_for_server.lock().await.push(buffer[..length].to_vec());
                    let _ = intercept_task.send_to(&buffer[..length], client_addr).await;
                } else {
                    let _ = intercept_task.send_to(&buffer[..length], server_addr).await;
                }
            }
        });
        let _echo = spawn_echo(server, server_addr, KEY_128, cipher, None);
        client
            .connect(intercept_addr)
            .await
            .expect("client to intercept");
        let association = associate(client, intercept_addr, KEY_128, cipher);
        association
            .send(&echo_destination(), b"replay-me")
            .await
            .expect("send");
        let (_, payload) = tokio::time::timeout(Duration::from_secs(2), association.recv())
            .await
            .expect("timeout")
            .expect("first recv");
        assert_eq!(payload, b"replay-me");
        let captured = seen.lock().await.last().cloned().expect("captured reply");
        intercept
            .send_to(&captured, client_addr)
            .await
            .expect("replay");
        association
            .send(&echo_destination(), b"next")
            .await
            .expect("next send");
        let (_, payload) = tokio::time::timeout(Duration::from_secs(2), association.recv())
            .await
            .expect("timeout")
            .expect("next recv");
        assert_eq!(payload, b"next");
    }

    #[tokio::test]
    async fn pre_2022_udp_still_roundtrips() {
        let cipher = "aes-128-gcm";
        let password = "phase6c-password";
        let (client, _, server, server_addr) = bind_pair().await;
        let _echo = spawn_echo(server, server_addr, password, cipher, None);
        let association = associate(client, server_addr, password, cipher);
        let (_, payload) = exchange(&association, b"sip004").await;
        assert_eq!(payload, b"sip004");
    }

    #[tokio::test]
    async fn isolates_concurrent_clients() {
        let cipher = "2022-blake3-aes-128-gcm";
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("server");
        let server_addr = server.local_addr().expect("addr");
        let _echo = spawn_echo(server, server_addr, KEY_128, cipher, None);
        let mut clients = Vec::new();
        for index in 0..4_u8 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client");
            socket.connect(server_addr).await.expect("connect");
            let association = associate(socket, server_addr, KEY_128, cipher);
            let payload = [index; 8];
            let (_, returned) = exchange(&association, &payload).await;
            assert_eq!(returned, payload);
            clients.push(association);
        }
        for (index, association) in clients.iter().enumerate() {
            let payload = [u8::try_from(index).expect("index") + 40; 8];
            let (_, returned) = exchange(association, &payload).await;
            assert_eq!(returned, payload);
        }
    }

    #[test]
    fn destination_helpers_round_trip_ipv4() {
        let destination = echo_destination();
        assert_eq!(
            address_destination(destination_address(&destination)),
            destination
        );
        assert!(matches!(
            destination_address(&destination),
            Address::SocketAddress(_)
        ));
    }
}
