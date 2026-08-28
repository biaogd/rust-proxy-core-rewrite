use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::direct::DirectError;

use super::Socks5ProxyError;

pub(super) async fn password_auth<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), Socks5ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The pinned Go oracle casts the byte lengths to uint8 but still writes the
    // complete credential bytes. Preserve that unusual overlength wire shape.
    let username_length =
        u8::try_from(username.len() % 256).expect("a byte length modulo 256 always fits in u8");
    let password_length =
        u8::try_from(password.len() % 256).expect("a byte length modulo 256 always fits in u8");
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.extend_from_slice(&[1, username_length]);
    request.extend_from_slice(username.as_bytes());
    request.push(password_length);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).await.map_err(DirectError::Io)?;
    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .map_err(DirectError::Io)?;
    if response[1] != 0 {
        return Err(Socks5ProxyError::AuthenticationRejected);
    }
    Ok(())
}
