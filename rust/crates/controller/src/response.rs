use super::{
    BTreeMap, Body, Bytes, Config, HeaderValue, Method, Response, Serialize, StatusCode, Uri,
    header, json,
};

pub(super) async fn method_not_allowed() -> Response {
    json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        &json!({"message": "Method Not Allowed"}),
    )
}

pub(super) async fn not_found(method: Method) -> Response {
    if method == Method::GET {
        json_response(StatusCode::NOT_FOUND, &json!({"message": "Not Found"}))
    } else {
        method_not_allowed().await
    }
}

pub(super) fn query_parameters(uri: &Uri) -> BTreeMap<String, String> {
    uri.query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn json_line<T: Serialize>(value: &T) -> Bytes {
    let mut body = serde_json::to_vec(value)
        .unwrap_or_else(|_| br#"{"message":"controller JSON error"}"#.to_vec());
    body.push(b'\n');
    Bytes::from(body)
}

pub(super) fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(mut body) => {
            body.push(b'\n');
            typed_response(status, "application/json", Body::from(body))
        }
        Err(error) => plain_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(super) fn plain_response(status: StatusCode, message: &str) -> Response {
    typed_response(
        status,
        "text/plain; charset=utf-8",
        Body::from(message.to_owned()),
    )
}

pub(super) fn dns_message_response(message: Vec<u8>) -> Response {
    typed_response(
        StatusCode::OK,
        "application/dns-message",
        Body::from(message),
    )
}

pub(super) fn typed_response(
    status: StatusCode,
    content_type: &'static str,
    body: Body,
) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

pub(super) fn empty_response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub(super) fn dns_record_type(value: &str) -> Option<u16> {
    if value.is_empty() {
        return Some(1);
    }
    Some(match value {
        "None" => 0,
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "UINFO" => 100,
        "UID" => 101,
        "GID" => 102,
        "UNSPEC" => 103,
        "NID" => 104,
        "L32" => 105,
        "L64" => 106,
        "LP" => 107,
        "EUI48" => 108,
        "EUI64" => 109,
        "NXNAME" => 128,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "AMTRELAY" => 260,
        "TA" => 32768,
        "DLV" => 32769,
        "Reserved" => 65535,
        _ => return None,
    })
}

pub(super) fn config_snapshot(config: &Config) -> serde_json::Value {
    let authentication: Vec<_> = config
        .authentication
        .iter()
        .map(|user| format!("{}:{}", user.username, user.password))
        .collect();
    let skip_auth_prefixes: Vec<_> = config
        .skip_auth_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    let lan_allowed_ips: Vec<_> = config
        .lan_allowed_ips
        .iter()
        .map(ToString::to_string)
        .collect();
    let lan_disallowed_ips: Vec<_> = config
        .lan_disallowed_ips
        .iter()
        .map(ToString::to_string)
        .collect();
    json!({
        "port": config.port,
        "socks-port": config.socks_port,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": config.mixed_port,
        "authentication": authentication,
        "allow-lan": config.allow_lan,
        "bind-address": config.bind_address,
        "skip-auth-prefixes": skip_auth_prefixes,
        "lan-allowed-ips": lan_allowed_ips,
        "lan-disallowed-ips": lan_disallowed_ips,
        "mode": config.mode,
        "log-level": config.log_level,
        "ipv6": config.ipv6,
        "geodata-mode": config.geodata_mode,
        "interface-name": config.interface_name,
        "routing-mark": config.routing_mark,
        "tcp-concurrent": config.tcp_concurrent,
        "inbound-tfo": config.inbound_tfo,
        "inbound-mptcp": config.inbound_mptcp,
        "etag-support": true,
        "keep-alive-idle": config.keep_alive_idle,
        "keep-alive-interval": config.keep_alive_interval,
        "disable-keep-alive": config.disable_keep_alive
    })
}
