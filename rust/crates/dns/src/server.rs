use std::net::IpAddr;
use std::sync::Arc;

use rewrite_config::Config;
use rewrite_state::RuntimeState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::cache::skip_name;
use crate::enhancer::{checked_record_end, resource_record_end};
use crate::service::DnsService;
use crate::wire::parse_question;
use crate::{DNS_HEADER_LENGTH, DnsError, MAX_DNS_MESSAGE};

pub(crate) enum HostLookup {
    Addresses(Vec<IpAddr>),
    ExternalAlias(String),
}

pub(crate) struct Question {
    pub(crate) name: String,
    pub(crate) record_type: u16,
    pub(crate) class: u16,
    pub(crate) end: usize,
}

/// Serves DNS over UDP and TCP on sockets prepared by the runtime generation.
///
/// Existing listeners read the current configuration for every new query, so
/// an upstream-only reload does not require rebinding the local address.
pub async fn serve(
    tcp: TcpListener,
    udp: UdpSocket,
    service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let udp = Arc::new(udp);
    let mut tasks = JoinSet::new();
    let mut datagram = vec![0_u8; MAX_DNS_MESSAGE];

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            received = udp.recv_from(&mut datagram) => {
                match received {
                    Ok((length, peer)) => {
                        let query = datagram[..length].to_vec();
                        let socket = Arc::clone(&udp);
                        match local_query_disposition(&query) {
                            LocalQueryDisposition::Ignore => continue,
                            LocalQueryDisposition::Reject(response) => {
                                tasks.spawn(async move {
                                    let _ = socket.send_to(&response, peer).await;
                                });
                                continue;
                            }
                            LocalQueryDisposition::Accept => {}
                        }
                        let service = Arc::clone(&service);
                        let current = current_config(&config);
                        let state = Arc::clone(&state);
                        tasks.spawn(async move {
                            let Ok(current) = current else { return };
                            let response = service
                                .resolver
                                .resolve(&query, &current, &state)
                                .await;
                            let response = match response {
                                Ok(response) => local_response(&query, response, true),
                                Err(_) => server_failure_response(&query),
                            };
                            if let Ok(response) = response {
                                let _ = socket.send_to(&response, peer).await;
                            }
                        });
                    }
                    Err(error) => {
                        eprintln!("DNS UDP listener failed: {error}");
                        break;
                    }
                }
            }
            accepted = tcp.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let service = Arc::clone(&service);
                        let config = config.clone();
                        let state = Arc::clone(&state);
                        let connection_shutdown = shutdown.child_token();
                        tasks.spawn(async move {
                            serve_tcp_connection(
                                stream,
                                service,
                                config,
                                state,
                                connection_shutdown,
                            ).await;
                        });
                    }
                    Err(error) => {
                        eprintln!("DNS TCP listener failed: {error}");
                        break;
                    }
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    eprintln!("DNS task failed: {error}");
                }
            }
        }
    }

    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
}

pub(crate) async fn serve_tcp_connection(
    mut stream: TcpStream,
    service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    loop {
        let mut length = [0_u8; 2];
        let read = tokio::select! {
            () = shutdown.cancelled() => return,
            result = stream.read_exact(&mut length) => result,
        };
        if read.is_err() {
            return;
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 {
            return;
        }
        let mut query = vec![0_u8; length];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        match local_query_disposition(&query) {
            LocalQueryDisposition::Ignore => continue,
            LocalQueryDisposition::Reject(response) => {
                if write_tcp_response(&mut stream, &response).await.is_err() {
                    return;
                }
                continue;
            }
            LocalQueryDisposition::Accept => {}
        }
        let Ok(current) = current_config(&config) else {
            return;
        };
        let response = service.resolver.resolve(&query, &current, &state).await;
        let response = match response {
            Ok(response) => local_response(&query, response, false),
            Err(_) => server_failure_response(&query),
        };
        let Ok(response) = response else { return };
        if write_tcp_response(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

pub(crate) async fn write_tcp_response(
    stream: &mut TcpStream,
    response: &[u8],
) -> Result<(), DnsError> {
    let length = u16::try_from(response.len())
        .map_err(|_| DnsError::InvalidMessage("response exceeds TCP DNS frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(response).await?;
    Ok(())
}

pub(crate) fn current_config(
    config: &watch::Receiver<Arc<Config>>,
) -> Result<Arc<Config>, DnsError> {
    let current = Arc::clone(&config.borrow());
    current.dns.as_ref().ok_or(DnsError::Inactive)?;
    Ok(current)
}

pub(crate) fn server_failure_response(query: &[u8]) -> Result<Vec<u8>, DnsError> {
    let question = parse_question(query)?;
    let mut response = query[..question.end].to_vec();
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = (query[3] & 0xf0) | 0x02;
    response[6..12].fill(0);
    Ok(response)
}

pub(crate) enum LocalQueryDisposition {
    Accept,
    Ignore,
    Reject(Vec<u8>),
}

pub(crate) fn local_query_disposition(query: &[u8]) -> LocalQueryDisposition {
    if query.len() < DNS_HEADER_LENGTH {
        return LocalQueryDisposition::Ignore;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return LocalQueryDisposition::Ignore;
    }
    let opcode = (flags >> 11) & 0x0f;
    if !matches!(opcode, 0 | 4) {
        return LocalQueryDisposition::Reject(local_rejection_response(query, 4, true));
    }
    let questions = u16::from_be_bytes([query[4], query[5]]);
    let answers = u16::from_be_bytes([query[6], query[7]]);
    let authorities = u16::from_be_bytes([query[8], query[9]]);
    let additionals = u16::from_be_bytes([query[10], query[11]]);
    if questions != 1 || answers > 1 || authorities > 1 || additionals > 2 {
        return LocalQueryDisposition::Reject(local_rejection_response(query, 1, false));
    }
    if validate_dns_wire(query).is_err() {
        return LocalQueryDisposition::Reject(local_rejection_response(query, 1, false));
    }
    LocalQueryDisposition::Accept
}

pub(crate) fn local_rejection_response(query: &[u8], rcode: u8, preserve_opcode: bool) -> Vec<u8> {
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let mut flags = 0x8000 | (request_flags & 0x03b0) | u16::from(rcode);
    if preserve_opcode {
        flags |= request_flags & 0x7800;
    }
    let mut response = Vec::with_capacity(DNS_HEADER_LENGTH);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&[0; 8]);
    response
}

pub(crate) fn validate_dns_wire(message: &[u8]) -> Result<(), DnsError> {
    let counts = [
        usize::from(u16::from_be_bytes([message[4], message[5]])),
        usize::from(u16::from_be_bytes([message[6], message[7]])),
        usize::from(u16::from_be_bytes([message[8], message[9]])),
        usize::from(u16::from_be_bytes([message[10], message[11]])),
    ];
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..counts[0] {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    for _ in 0..counts[1] + counts[2] + counts[3] {
        offset = resource_record_end(message, offset)?.1;
    }
    if offset > message.len() {
        return Err(DnsError::InvalidMessage("DNS message is truncated"));
    }
    Ok(())
}

pub(crate) fn local_response(
    query: &[u8],
    mut response: Vec<u8>,
    udp: bool,
) -> Result<Vec<u8>, DnsError> {
    if let Some((_, request_do)) = message_edns(query)?
        && message_edns(&response)?.is_none()
    {
        append_edns(&mut response, 1232, request_do)?;
    }
    if udp {
        let limit = message_edns(query)?.map_or(512, |(size, _)| usize::from(size));
        truncate_udp_response(&response, limit.max(512))
    } else {
        Ok(response)
    }
}

pub(crate) fn message_edns(message: &[u8]) -> Result<Option<(u16, bool)>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answers = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let authorities = usize::from(u16::from_be_bytes([message[8], message[9]]));
    let additionals = usize::from(u16::from_be_bytes([message[10], message[11]]));
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    for _ in 0..answers + authorities {
        offset = resource_record_end(message, offset)?.1;
    }
    for _ in 0..additionals {
        let name_end = skip_name(message, offset)?;
        if name_end + 10 > message.len() {
            return Err(DnsError::InvalidMessage("resource record is truncated"));
        }
        let record_type = u16::from_be_bytes([message[name_end], message[name_end + 1]]);
        let class = u16::from_be_bytes([message[name_end + 2], message[name_end + 3]]);
        let ttl = u32::from_be_bytes([
            message[name_end + 4],
            message[name_end + 5],
            message[name_end + 6],
            message[name_end + 7],
        ]);
        let end = resource_record_end(message, offset)?.1;
        if record_type == 41 {
            return Ok(Some((class, ttl & 0x8000 != 0)));
        }
        offset = end;
    }
    Ok(None)
}

pub(crate) fn append_edns(
    response: &mut Vec<u8>,
    udp_size: u16,
    dnssec_ok: bool,
) -> Result<(), DnsError> {
    let additionals = u16::from_be_bytes([response[10], response[11]])
        .checked_add(1)
        .ok_or(DnsError::InvalidMessage("too many additional records"))?;
    response[10..12].copy_from_slice(&additionals.to_be_bytes());
    response.push(0);
    response.extend_from_slice(&41_u16.to_be_bytes());
    response.extend_from_slice(&udp_size.to_be_bytes());
    response.extend_from_slice(&(if dnssec_ok { 0x8000_u32 } else { 0 }).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    Ok(())
}

pub(crate) fn truncate_udp_response(message: &[u8], limit: usize) -> Result<Vec<u8>, DnsError> {
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let counts = [
        usize::from(u16::from_be_bytes([message[6], message[7]])),
        usize::from(u16::from_be_bytes([message[8], message[9]])),
        usize::from(u16::from_be_bytes([message[10], message[11]])),
    ];
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    let question_end = offset;
    let mut sections = [Vec::new(), Vec::new(), Vec::new()];
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let start = offset;
            let (record_type, end) = resource_record_end(message, start)?;
            sections[section].push((record_type, start, end));
            offset = end;
        }
    }

    if sections[2]
        .last()
        .is_some_and(|(record_type, _, _)| *record_type == 250)
        || message.len() <= limit
    {
        return Ok(message.to_vec());
    }

    let edns = sections[2]
        .iter()
        .rposition(|(record_type, _, _)| *record_type == 41)
        .map(|index| sections[2].remove(index));
    let edns_length = edns.map_or(0, |(_, start, end)| end - start);
    let budget = limit.saturating_sub(edns_length);
    let mut response = message[..question_end].to_vec();
    let mut retained = [0_u16; 3];
    let mut exhausted = false;
    let mut omitted = false;
    for (section_index, section) in sections.iter().enumerate() {
        for &(_, start, end) in section {
            if !exhausted && response.len() + end - start <= budget {
                response.extend_from_slice(&message[start..end]);
                retained[section_index] += 1;
            } else {
                exhausted = true;
                omitted = true;
            }
        }
    }
    if let Some((_, start, end)) = edns {
        response.extend_from_slice(&message[start..end]);
        retained[2] += 1;
    }
    response[6..8].copy_from_slice(&retained[0].to_be_bytes());
    response[8..10].copy_from_slice(&retained[1].to_be_bytes());
    response[10..12].copy_from_slice(&retained[2].to_be_bytes());
    if omitted {
        response[2] |= 0x02;
    }
    Ok(response)
}
