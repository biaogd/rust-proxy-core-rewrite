//! `plain` obfs plugin — identity transform.

use rewrite_io::BoxedStream;

pub(crate) fn wrap(stream: BoxedStream) -> BoxedStream {
    stream
}
