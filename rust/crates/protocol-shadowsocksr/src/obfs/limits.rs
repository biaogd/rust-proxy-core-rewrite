//! Shared pre-handshake backpressure and deadline for TCP camouflage obfs.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::time::{Sleep, sleep};

/// Max application bytes queued before the peer answers the camouflage handshake.
pub(crate) const PRE_HANDSHAKE_BUF_MAX: usize = 256 * 1024;

/// Wall-clock limit from the first camouflage write until handshake completes.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct HandshakeDeadline {
    started: Instant,
    sleep: Option<Pin<Box<Sleep>>>,
}

pub(crate) type HandshakeDeadlineSlot = Option<HandshakeDeadline>;

pub(crate) fn arm_handshake_deadline(slot: &mut HandshakeDeadlineSlot) {
    if slot.is_none() {
        *slot = Some(HandshakeDeadline {
            started: Instant::now(),
            sleep: None,
        });
    }
}

pub(crate) fn clear_handshake_deadline(slot: &mut HandshakeDeadlineSlot) {
    *slot = None;
}

pub(crate) fn poll_handshake_deadline(
    slot: &mut HandshakeDeadlineSlot,
    complete: bool,
    cx: &mut Context<'_>,
    obfs: &str,
) -> Poll<Result<(), io::Error>> {
    if complete {
        clear_handshake_deadline(slot);
        return Poll::Ready(Ok(()));
    }
    let Some(state) = slot.as_mut() else {
        return Poll::Ready(Ok(()));
    };
    if state.started.elapsed() >= HANDSHAKE_TIMEOUT {
        return Poll::Ready(Err(handshake_timeout_error(obfs)));
    }
    // Arm a Tokio sleep so mute peers still wake the task at the deadline.
    // Sync unit tests without a runtime rely on Instant alone.
    if state.sleep.is_none() && tokio::runtime::Handle::try_current().is_ok() {
        let remaining = HANDSHAKE_TIMEOUT.saturating_sub(state.started.elapsed());
        state.sleep = Some(Box::pin(sleep(remaining)));
    }
    if let Some(timer) = state.sleep.as_mut() {
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => return Poll::Ready(Err(handshake_timeout_error(obfs))),
            Poll::Pending => {}
        }
    }
    Poll::Ready(Ok(()))
}

/// Test helper: force an already-armed deadline into the past.
#[cfg(test)]
pub(crate) fn force_deadline_elapsed(slot: &mut HandshakeDeadlineSlot) {
    let started = Instant::now()
        .checked_sub(HANDSHAKE_TIMEOUT)
        .and_then(|t| t.checked_sub(Duration::from_secs(1)))
        .expect("handshake timeout fits Instant span");
    if let Some(state) = slot.as_mut() {
        state.started = started;
        state.sleep = None;
    } else {
        *slot = Some(HandshakeDeadline {
            started,
            sleep: None,
        });
    }
}

pub(crate) fn handshake_timeout_error(obfs: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("{obfs} camouflage handshake timed out"),
    )
}

pub(crate) fn drop_on_shutdown_error(obfs: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{obfs} shutdown would drop pre-handshake payload"),
    )
}

pub(crate) fn buffer_cap_error(obfs: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!("{obfs} pre-handshake buffer exceeded {PRE_HANDSHAKE_BUF_MAX} bytes"),
    )
}

/// Park a write that returned `Pending` at the pre-handshake buffer cap.
pub(crate) fn park_write_waker(slot: &mut Option<Waker>, cx: &Context<'_>) {
    let waker = cx.waker();
    if slot
        .as_ref()
        .is_none_or(|existing| !existing.will_wake(waker))
    {
        *slot = Some(waker.clone());
    }
}

/// Wake a writer blocked on the pre-handshake buffer (handshake done / freed / failed).
pub(crate) fn wake_write_waker(slot: &mut Option<Waker>) {
    if let Some(waker) = slot.take() {
        waker.wake();
    }
}
