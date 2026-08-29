use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::cipher::{
    StreamCipherEngine, StreamCipherKind, StreamCipherSpec, new_decrypt_engine, new_encrypt_engine,
    pick_stream_cipher,
};

pub(crate) struct StreamCipherIo<S> {
    inner: S,
    spec: StreamCipherSpec,
    write_iv: Option<Vec<u8>>,
    write_iv_sent: bool,
    write_cipher: Option<StreamCipherEngine>,
    read_iv: Option<Vec<u8>>,
    read_cipher: Option<StreamCipherEngine>,
    read_stash: Vec<u8>,
}

impl<S> StreamCipherIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(
        inner: S,
        cipher: &str,
        password: &str,
    ) -> Result<Self, super::cipher::CipherError> {
        Ok(Self {
            inner,
            spec: pick_stream_cipher(cipher, password)?,
            write_iv: None,
            write_iv_sent: false,
            write_cipher: None,
            read_iv: None,
            read_cipher: None,
            read_stash: Vec::new(),
        })
    }

    pub(crate) fn write_iv(&self) -> &[u8] {
        self.write_iv.as_deref().unwrap_or(&[])
    }

    pub(crate) fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub(crate) fn ensure_write_iv(&mut self) {
        if self.spec.iv_size > 0 && self.write_iv.is_none() {
            let mut iv = vec![0_u8; self.spec.iv_size];
            rand::rng().fill(&mut iv[..]);
            self.write_iv = Some(iv);
            self.write_cipher = Some(
                new_encrypt_engine(&self.spec, self.write_iv.as_ref().expect("write iv"))
                    .expect("write cipher initialized"),
            );
        } else if self.spec.iv_size == 0 && self.write_cipher.is_none() {
            self.write_cipher =
                Some(new_encrypt_engine(&self.spec, &[]).expect("write cipher initialized"));
        }
    }

    pub(crate) async fn write_plain(&mut self, payload: &[u8]) -> io::Result<()> {
        self.ensure_write_iv();
        if self.spec.iv_size > 0 && !self.write_iv_sent {
            tokio::io::AsyncWriteExt::write_all(
                &mut self.inner,
                self.write_iv.as_ref().expect("iv"),
            )
            .await?;
            self.write_iv_sent = true;
        }
        if payload.is_empty() {
            return Ok(());
        }
        let encrypted = self.encrypt(payload);
        tokio::io::AsyncWriteExt::write_all(&mut self.inner, &encrypted).await
    }

    pub(crate) fn encrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        if self.spec.kind == StreamCipherKind::Dummy {
            return payload.to_vec();
        }
        let mut output = payload.to_vec();
        self.write_cipher
            .as_mut()
            .expect("write cipher initialized")
            .encrypt(&mut output);
        output
    }

    pub(crate) fn push_cipher_bytes(&mut self, chunk: &[u8]) {
        self.read_stash.extend_from_slice(chunk);
    }

    pub(crate) fn take_plain_bytes(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.spec.kind == StreamCipherKind::Dummy {
            if self.read_stash.is_empty() {
                return Ok(None);
            }
            return Ok(Some(std::mem::take(&mut self.read_stash)));
        }
        if self.read_iv.is_none() {
            if self.read_stash.len() < self.spec.iv_size {
                return Ok(None);
            }
            self.read_iv = Some(self.read_stash[..self.spec.iv_size].to_vec());
            self.read_stash.drain(..self.spec.iv_size);
            self.read_cipher = Some(new_decrypt_engine(
                &self.spec,
                self.read_iv.as_ref().expect("read iv"),
            )?);
        }
        if self.read_stash.is_empty() {
            return Ok(None);
        }
        let mut plain = std::mem::take(&mut self.read_stash);
        self.read_cipher
            .as_mut()
            .expect("read cipher initialized")
            .decrypt(&mut plain);
        Ok(Some(plain))
    }
}

impl<S> AsyncWrite for StreamCipherIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other(
            "stream cipher io requires SsrStream",
        )))
    }
}

impl<S> AsyncRead for StreamCipherIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other(
            "stream cipher io requires SsrStream",
        )))
    }
}
