//! Bounded network-order framing. A failed/cancelled operation poisons the stream.
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

pub const MAX_RECORD: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame length exceeds configured limit")]
    TooLarge,
    #[error("frame operation timed out")]
    Timeout,
    #[error("stream is closed after a failed or cancelled operation")]
    Closed,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Sequential frame transport. Drop the whole connection after any error.
/// Cancellation leaves `usable` false, preventing reuse after a partial read/write.
pub struct Framed<S> {
    stream: S,
    max: usize,
    deadline: Duration,
    usable: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Framed<S> {
    pub fn new(stream: S, max: usize, deadline: Duration) -> Result<Self, FrameError> {
        if max == 0 || max > MAX_RECORD {
            return Err(FrameError::TooLarge);
        }
        Ok(Self {
            stream,
            max,
            deadline,
            usable: true,
        })
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, FrameError> {
        if !self.usable {
            return Err(FrameError::Closed);
        }
        self.usable = false;
        let result = timeout(self.deadline, async {
            let length = self.stream.read_u32().await? as usize;
            if length > self.max {
                return Err(FrameError::TooLarge);
            }
            let mut bytes = vec![0; length];
            self.stream.read_exact(&mut bytes).await?;
            Ok(bytes)
        })
        .await
        .map_err(|_| FrameError::Timeout)?;
        if result.is_ok() {
            self.usable = true;
        }
        result
    }

    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        if !self.usable {
            return Err(FrameError::Closed);
        }
        self.usable = false;
        if bytes.len() > self.max {
            return Err(FrameError::TooLarge);
        }
        let result = timeout(self.deadline, async {
            self.stream.write_u32(bytes.len() as u32).await?;
            self.stream.write_all(bytes).await?;
            self.stream.flush().await?;
            Ok::<(), FrameError>(())
        })
        .await
        .map_err(|_| FrameError::Timeout)?;
        if result.is_ok() {
            self.usable = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fragmented_and_consecutive_frames() {
        let (mut peer, io) = tokio::io::duplex(2);
        let writer = tokio::spawn(async move {
            for b in [0, 0, 0, 3, 10, 11, 12, 0, 0, 0, 1, 13] {
                peer.write_all(&[b]).await.unwrap();
            }
        });
        let mut frames = Framed::new(io, 8, Duration::from_secs(1)).unwrap();
        assert_eq!(frames.receive().await.unwrap(), [10, 11, 12]);
        assert_eq!(frames.receive().await.unwrap(), [13]);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_length_before_reading_body() {
        let (mut peer, io) = tokio::io::duplex(8);
        peer.write_u32(u32::MAX).await.unwrap();
        let mut frames = Framed::new(io, 8, Duration::from_secs(1)).unwrap();
        assert!(matches!(frames.receive().await, Err(FrameError::TooLarge)));
        assert!(matches!(frames.receive().await, Err(FrameError::Closed)));
    }

    #[tokio::test]
    async fn truncation_and_cancellation_close_transport() {
        let (mut peer, io) = tokio::io::duplex(8);
        peer.write_all(&[0, 0, 0, 3, 1]).await.unwrap();
        drop(peer);
        let mut frames = Framed::new(io, 8, Duration::from_secs(1)).unwrap();
        assert!(matches!(frames.receive().await, Err(FrameError::Io(_))));
        assert!(matches!(frames.send(b"x").await, Err(FrameError::Closed)));

        let (_peer, io) = tokio::io::duplex(8);
        let mut frames = Framed::new(io, 8, Duration::from_secs(10)).unwrap();
        assert!(
            timeout(Duration::from_millis(10), frames.receive())
                .await
                .is_err()
        );
        assert!(matches!(frames.receive().await, Err(FrameError::Closed)));
    }

    #[tokio::test]
    async fn write_roundtrip_and_internal_timeout() {
        let (a, b) = tokio::io::duplex(32);
        let mut sender = Framed::new(a, 8, Duration::from_secs(1)).unwrap();
        let mut receiver = Framed::new(b, 8, Duration::from_millis(10)).unwrap();
        sender.send(b"hello").await.unwrap();
        assert_eq!(receiver.receive().await.unwrap(), b"hello");
        assert!(matches!(receiver.receive().await, Err(FrameError::Timeout)));
        assert!(matches!(receiver.receive().await, Err(FrameError::Closed)));
    }
}
