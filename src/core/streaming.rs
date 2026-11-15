use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::BufferPlan;

/// A bounded pool of read/write buffers.  A permit is held for the lifetime
/// of a lease, making the maximum allocated transfer memory explicit.
#[derive(Clone)]
pub struct BufferPool {
    buffer_size: usize,
    max_in_flight_bytes: usize,
    permits: Arc<Semaphore>,
}

impl BufferPool {
    pub fn new(plan: &BufferPlan) -> io::Result<Self> {
        if plan.buffer_size_bytes == 0
            || plan.max_in_flight_bytes == 0
            || plan.max_in_flight_bytes < plan.buffer_size_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer plan must have non-zero limits and fit one buffer",
            ));
        }

        let slots = (plan.max_in_flight_bytes / plan.buffer_size_bytes).max(1);
        let bounded_bytes = slots.saturating_mul(plan.buffer_size_bytes);
        Ok(Self {
            buffer_size: plan.buffer_size_bytes,
            max_in_flight_bytes: bounded_bytes,
            permits: Arc::new(Semaphore::new(slots)),
        })
    }

    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    pub fn max_in_flight_bytes(&self) -> usize {
        self.max_in_flight_bytes
    }

    pub async fn acquire(&self) -> io::Result<BufferLease> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "buffer pool closed"))?;
        Ok(BufferLease {
            buffer: vec![0; self.buffer_size],
            _permit: permit,
        })
    }
}

pub struct BufferLease {
    buffer: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

impl BufferLease {
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn into_inner(self) -> Vec<u8> {
        // Keep the permit alive until after the buffer is moved out.  Dropping
        // the permit at the end of this function returns the slot to the pool.
        let Self { buffer, _permit } = self;
        buffer
    }
}

/// Cooperative pause/cancel state shared by the sender and receiver.
#[derive(Clone, Default)]
pub struct TransferControl {
    paused: Arc<std::sync::atomic::AtomicBool>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    resume_notify: Arc<Notify>,
}

impl TransferControl {
    pub fn pause(&self) {
        self.paused
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn resume(&self) {
        self.paused
            .store(false, std::sync::atomic::Ordering::Release);
        self.resume_notify.notify_waiters();
    }

    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.resume_notify.notify_waiters();
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn wait_if_paused(&self) -> io::Result<()> {
        loop {
            // Register before checking the state to avoid losing notify_waiters
            // between the atomic load and polling Notified.
            let notified = self.resume_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "transfer cancelled while paused",
                ));
            }
            if !self.is_paused() {
                return Ok(());
            }
            notified.await;
        }
    }

    pub async fn wait_until_cancelled(&self) {
        loop {
            let notified = self.resume_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone, Debug)]
pub struct CopyProgress {
    pub bytes_copied: u64,
    pub elapsed: Duration,
    pub bytes_per_second: f64,
}

#[derive(Clone, Debug, Default)]
pub struct CopyStats {
    pub bytes_copied: u64,
    pub elapsed: Duration,
}

impl CopyStats {
    pub fn bytes_per_second(&self) -> f64 {
        let seconds = self.elapsed.as_secs_f64();
        if seconds > 0.0 {
            self.bytes_copied as f64 / seconds
        } else {
            0.0
        }
    }
}

/// Copy an async stream using exactly one bounded lease.  The callback is
/// synchronous and runs after each write, so callers can forward progress to
/// a GUI channel without coupling the streaming layer to egui.
pub async fn copy_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    pool: &BufferPool,
    control: &TransferControl,
    mut on_progress: F,
) -> io::Result<CopyStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(CopyProgress) + Send,
{
    let mut lease = pool.acquire().await?;
    let started = Instant::now();
    let mut bytes_copied = 0_u64;

    loop {
        control.wait_if_paused().await?;
        let read = reader.read(lease.as_mut_slice()).await?;
        if read == 0 {
            break;
        }

        writer.write_all(&lease.as_mut_slice()[..read]).await?;
        bytes_copied = bytes_copied.saturating_add(read as u64);
        let elapsed = started.elapsed();
        on_progress(CopyProgress {
            bytes_copied,
            elapsed,
            bytes_per_second: if elapsed.is_zero() {
                0.0
            } else {
                bytes_copied as f64 / elapsed.as_secs_f64()
            },
        });
    }

    writer.flush().await?;
    Ok(CopyStats {
        bytes_copied,
        elapsed: started.elapsed(),
    })
}
