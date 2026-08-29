use std::fs;
use std::io::{BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Response, StatusCode};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;

#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Wire-level contract records independent request predicates.
struct RequestObservation {
    method: String,
    scheme: Option<String>,
    authority_matches_listener: bool,
    path: String,
    query_keys: Vec<String>,
    accept: Option<String>,
    dns_id_zero: bool,
    request_body_empty: bool,
    valid: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Observation {
    connections: usize,
    negotiated_protocols: Vec<Option<String>>,
    server_names: Vec<Option<String>>,
    queries: usize,
    requests: Vec<RequestObservation>,
}

struct SharedObservation {
    output: PathBuf,
    state: Mutex<Observation>,
}

impl SharedObservation {
    fn update(&self, update: impl FnOnce(&mut Observation)) {
        let snapshot = {
            let mut state = self.state.lock().expect("observation lock");
            update(&mut state);
            state.clone()
        };
        let encoded = serde_json::to_vec_pretty(&snapshot).expect("serialize observation");
        fs::write(&self.output, encoded).expect("write observation");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut arguments = std::env::args_os().skip(1);
    let cert_path = arguments.next().ok_or("missing certificate path")?;
    let key_path = arguments.next().ok_or("missing private-key path")?;
    let output = PathBuf::from(arguments.next().ok_or("missing observation path")?);
    if arguments.next().is_some() {
        return Err("unexpected authority argument".into());
    }

    let certificates = rustls_pemfile::certs(&mut BufReader::new(fs::File::open(cert_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(key_path)?))?
        .ok_or("private key is missing")?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listener_address = listener.local_addr()?;
    let state = Arc::new(SharedObservation {
        output,
        state: Mutex::new(Observation::default()),
    });
    state.update(|_| {});
    println!("{}", listener_address.port());
    std::io::stdout().flush()?;

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            record_connection(&state, &stream);
            let _ = serve_h2(stream, state, listener_address).await;
        });
    }
}

fn record_connection(state: &SharedObservation, stream: &TlsStream<TcpStream>) {
    let connection = stream.get_ref().1;
    let protocol = connection
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).into_owned());
    let server_name = connection.server_name().map(ToOwned::to_owned);
    state.update(|observation| {
        observation.connections += 1;
        observation.negotiated_protocols.push(protocol);
        observation.server_names.push(server_name);
    });
}

async fn serve_h2(
    stream: TlsStream<TcpStream>,
    state: Arc<SharedObservation>,
    listener_address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut connection = h2::server::handshake(stream).await?;
    while let Some(result) = connection.accept().await {
        let (request, mut respond) = result?;
        let method = request.method().to_string();
        let scheme = request.uri().scheme_str().map(ToOwned::to_owned);
        let authority = request.uri().authority().map(ToString::to_string);
        let path = request.uri().path().to_owned();
        let query = request.uri().query().unwrap_or_default();
        let parameters = query
            .split('&')
            .filter(|parameter| !parameter.is_empty())
            .filter_map(|parameter| parameter.split_once('='))
            .collect::<Vec<_>>();
        let encoded = parameters
            .iter()
            .find_map(|(name, value)| (*name == "dns").then_some(*value))
            .unwrap_or_default();
        let dns_query = URL_SAFE_NO_PAD.decode(encoded).unwrap_or_default();
        let request_body_empty = request.body().is_end_stream();
        let accept = request
            .headers()
            .get("accept")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let query_keys = parameters
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect::<Vec<_>>();
        let valid = method == "GET"
            && scheme.as_deref() == Some("https")
            && authority.as_deref() == Some(&listener_address.to_string())
            && path == "/dns-query"
            && query_keys == ["dns"]
            && accept.as_deref() == Some("application/dns-message")
            && dns_query.len() >= 12
            && dns_query[..2] == [0, 0]
            && request_body_empty;
        state.update(|observation| {
            observation.requests.push(RequestObservation {
                method,
                scheme,
                authority_matches_listener: authority.as_deref()
                    == Some(&listener_address.to_string()),
                path,
                query_keys,
                accept,
                dns_id_zero: dns_query.get(..2) == Some(&[0, 0]),
                request_body_empty,
                valid,
            });
        });
        if !valid {
            let response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())?;
            respond.send_response(response, true)?;
            continue;
        }
        let dns_response = answer(&dns_query)?;
        state.update(|observation| observation.queries += 1);
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/dns-message")
            .body(())?;
        let mut body = respond.send_response(response, false)?;
        body.send_data(Bytes::from(dns_response), true)?;
    }
    Ok(())
}

fn answer(query: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let question_end = dns_question_end(query).ok_or("invalid DNS question")?;
    let mut response = query[..2].to_vec();
    response.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 192, 0, 2, 42,
    ]);
    Ok(response)
}

fn dns_question_end(message: &[u8]) -> Option<usize> {
    if message.len() < 12 {
        return None;
    }
    let mut offset = 12;
    loop {
        let length = usize::from(*message.get(offset)?);
        offset += 1;
        if length == 0 {
            return (offset + 4 <= message.len()).then_some(offset + 4);
        }
        if length > 63 || offset + length > message.len() {
            return None;
        }
        offset += length;
    }
}
