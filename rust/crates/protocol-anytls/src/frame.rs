//! `AnyTLS` session-layer frame helpers.

pub(crate) const CMD_WASTE: u8 = 0;
pub(crate) const CMD_SYN: u8 = 1;
pub(crate) const CMD_PSH: u8 = 2;
pub(crate) const CMD_FIN: u8 = 3;
pub(crate) const CMD_SETTINGS: u8 = 4;
pub(crate) const CMD_ALERT: u8 = 5;
pub(crate) const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub(crate) const CMD_SYNACK: u8 = 7;
pub(crate) const CMD_HEART_REQUEST: u8 = 8;
pub(crate) const CMD_HEART_RESPONSE: u8 = 9;
pub(crate) const CMD_SERVER_SETTINGS: u8 = 10;

pub(crate) const HEADER_OVERHEAD: usize = 1 + 4 + 2;
pub(crate) const MAX_FRAME_DATA_LEN: usize = 0xFFFF;

#[derive(Clone, Debug)]
pub(crate) struct Frame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

impl Frame {
    pub(crate) fn new(cmd: u8, sid: u32) -> Self {
        Self {
            cmd,
            sid,
            data: Vec::new(),
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_OVERHEAD + self.data.len());
        out.push(self.cmd);
        out.extend_from_slice(&self.sid.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(self.data.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.data);
        out
    }
}

pub(crate) fn encode_settings(client_metadata: &str, padding_md5: &str) -> Vec<u8> {
    // Key order is not significant on the wire; servers parse by key.
    format!("v=2\nclient={client_metadata}\npadding-md5={padding_md5}").into_bytes()
}

pub(crate) fn encode_socks_address(
    destination: &rewrite_model::Destination,
) -> Result<Vec<u8>, crate::AnyTlsProtocolError> {
    use rewrite_model::Host;
    let mut out = Vec::with_capacity(32);
    match &destination.host {
        Host::Ip(std::net::IpAddr::V4(address)) => {
            out.push(1);
            out.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| crate::AnyTlsProtocolError::DomainTooLong)?;
            out.extend_from_slice(&[3, length]);
            out.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V6(address)) => {
            out.push(4);
            out.extend_from_slice(&address.octets());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(out)
}
