use std::collections::BTreeMap;
use std::io;

use http::{Method, Request, Uri};
use rand::RngExt as _;

use crate::BoxedStream;
use crate::v2ray_h2::connect_h2_request;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpStreamOneOptions {
    pub host: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub no_grpc_header: bool,
    pub padding_min: usize,
    pub padding_max: usize,
}

/// Opens the common xHTTP `stream-one` carrier over an established HTTP/2 connection.
///
/// # Errors
///
/// Returns an error for invalid request metadata or an HTTP/2 handshake failure.
pub async fn connect_xhttp_stream_one(
    stream: BoxedStream,
    options: &XHttpStreamOneOptions,
) -> io::Result<BoxedStream> {
    let uri: Uri = format!("https://{}{}", options.host, options.path)
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut request = Request::builder().method(Method::POST).uri(uri);
    for (name, value) in &options.headers {
        request = request.header(name, value);
    }
    if !options.no_grpc_header {
        request = request.header("content-type", "application/grpc");
    }
    let padding_length = if options.padding_min == options.padding_max {
        options.padding_min
    } else {
        rand::rng().random_range(options.padding_min..=options.padding_max)
    };
    let separator = if options.path.contains('?') { '&' } else { '?' };
    request = request.header(
        "referer",
        format!(
            "https://{}{}{}x_padding={}",
            options.host,
            options.path,
            separator,
            "X".repeat(padding_length)
        ),
    );
    let request = request
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    connect_h2_request(stream, request).await
}
