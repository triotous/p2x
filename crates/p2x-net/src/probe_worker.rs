use crate::probe::{MAX_HEADER, ProbeError, ProbeHeader, ProbeMode, decode_header, pattern_byte};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};

pub const BUFFER_SIZE: usize = 32 * 1024;
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn read_frame_async<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, ProbeError> {
    let length = reader.read_u32().await.map_err(|_| ProbeError::Truncated)? as usize;
    if length > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| ProbeError::Truncated)?;
    Ok(body)
}

pub async fn write_frame_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), ProbeError> {
    if body.len() > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    writer
        .write_u32(body.len() as u32)
        .await
        .map_err(|_| ProbeError::Truncated)?;
    writer
        .write_all(body)
        .await
        .map_err(|_| ProbeError::Truncated)
}

pub async fn stream_pattern<W: AsyncWrite + Unpin>(writer: &mut W, length: u64) -> io::Result<u64> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(buffer.len() as u64) as usize;
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = pattern_byte(offset + index as u64);
        }
        writer.write_all(&buffer[..count]).await?;
        offset += count as u64;
    }
    Ok(offset)
}

pub async fn execute_header<R, W>(reader: &mut R, writer: &mut W) -> Result<ProbeHeader, ProbeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let frame = timeout(WORKER_TIMEOUT, read_frame_async(reader))
        .await
        .map_err(|_| ProbeError::Timeout)??;
    let header = decode_header(&frame)?;
    if header.mode == ProbeMode::NonceEcho {
        let ack =
            serde_json::to_vec(&header).map_err(|error| ProbeError::Invalid(error.to_string()))?;
        write_frame_async(writer, &ack).await?;
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn async_frames_reject_oversized_before_allocation() {
        let (mut writer, mut reader) = duplex(32);
        writer.write_u32((MAX_HEADER as u32) + 1).await.unwrap();
        drop(writer);
        assert_eq!(
            read_frame_async(&mut reader).await,
            Err(ProbeError::TooLarge)
        );
    }

    #[tokio::test]
    async fn pattern_stream_uses_bounded_output() {
        let (mut writer, mut reader) = duplex(BUFFER_SIZE * 2);
        let task =
            tokio::spawn(async move { stream_pattern(&mut writer, 256 * 1024).await.unwrap() });
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(task.await.unwrap(), received.len() as u64);
        assert_eq!(received[251], 0);
    }
}
