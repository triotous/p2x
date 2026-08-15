use crate::probe::{
    MAX_HEADER, MAX_TRANSFER, ProbeAck, ProbeError, ProbeHeader, ProbeMode, ProbePath,
    ProbeTerminal, SCHEMA_VERSION, decode_header, pattern_byte,
};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};

pub const BUFFER_SIZE: usize = 32 * 1024;
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(5);
const FNV_OFFSET: u64 = 1469598103934665603;
const FNV_PRIME: u64 = 1099511628211;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamStats {
    pub bytes: u64,
    pub hash: u64,
}

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

pub async fn stream_pattern<W: AsyncWrite + Unpin>(
    writer: &mut W,
    length: u64,
) -> io::Result<StreamStats> {
    stream_pattern_with_delay(writer, length, 0, 0).await
}

pub async fn stream_pattern_with_delay<W: AsyncWrite + Unpin>(
    writer: &mut W,
    length: u64,
    delay_ms: u32,
    chunk_size: u32,
) -> io::Result<StreamStats> {
    if length > MAX_TRANSFER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transfer exceeds configured limit",
        ));
    }
    let chunk_size = if chunk_size == 0 {
        BUFFER_SIZE
    } else {
        chunk_size as usize
    };
    if chunk_size > BUFFER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunk exceeds buffer limit",
        ));
    }
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut offset = 0;
    let mut hash = FNV_OFFSET;
    while offset < length {
        let count = (length - offset).min(chunk_size as u64) as usize;
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = pattern_byte(offset + index as u64);
            hash = (hash ^ *byte as u64).wrapping_mul(FNV_PRIME);
        }
        writer.write_all(&buffer[..count]).await?;
        offset += count as u64;
        if delay_ms != 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms as u64)).await;
        }
    }
    Ok(StreamStats {
        bytes: offset,
        hash,
    })
}

pub async fn read_pattern<R: AsyncRead + Unpin>(
    reader: &mut R,
    length: u64,
) -> io::Result<StreamStats> {
    if length > MAX_TRANSFER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transfer exceeds configured limit",
        ));
    }
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut remaining = length;
    let mut bytes = 0;
    let mut hash = FNV_OFFSET;
    while remaining != 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count]).await?;
        for byte in &buffer[..count] {
            hash = (hash ^ *byte as u64).wrapping_mul(FNV_PRIME);
        }
        remaining -= count as u64;
        bytes += count as u64;
    }
    Ok(StreamStats { bytes, hash })
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

pub async fn execute_probe<S>(
    stream: &mut S,
    path: ProbePath,
    connection_id_hash: u64,
) -> Result<ProbeAck, ProbeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = timeout(WORKER_TIMEOUT, read_frame_async(stream))
        .await
        .map_err(|_| ProbeError::Timeout)??;
    let header = decode_header(&frame)?;
    let written = match header.mode {
        ProbeMode::NonceEcho => StreamStats { bytes: 0, hash: 0 },
        ProbeMode::HalfClose => {
            let stats = stream_pattern(stream, header.length)
                .await
                .map_err(|_| ProbeError::Truncated)?;
            stream.shutdown().await.map_err(|_| ProbeError::Truncated)?;
            stats
        }
        ProbeMode::SlowReader => stream_pattern_with_delay(
            stream,
            header.length,
            header.slow_delay_ms,
            header.slow_chunk_size,
        )
        .await
        .map_err(|_| ProbeError::Truncated)?,
    };
    let ack = ProbeAck {
        schema_version: SCHEMA_VERSION,
        nonce: header.nonce,
        request_id: header.request_id,
        path,
        connection_id_hash,
        bytes_read: 0,
        bytes_written: written.bytes,
        read_hash: 0,
        write_hash: written.hash,
        half_close: header.mode == ProbeMode::HalfClose,
        terminal: ProbeTerminal::Ok,
    };
    let body = serde_json::to_vec(&ack).map_err(|error| ProbeError::Invalid(error.to_string()))?;
    write_frame_async(stream, &body).await?;
    Ok(ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex};

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
    async fn pattern_stream_uses_bounded_output_and_incremental_hash() {
        let (mut writer, mut reader) = duplex(BUFFER_SIZE * 2);
        let task =
            tokio::spawn(async move { stream_pattern(&mut writer, 256 * 1024).await.unwrap() });
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        let stats = task.await.unwrap();
        assert_eq!(stats.bytes, received.len() as u64);
        assert_eq!(received[251], 0);
        assert_eq!(stats.hash, stream_hash(&received));
    }

    #[tokio::test]
    async fn slow_reader_chunking_preserves_bytes_and_hash() {
        let (mut writer, mut reader) = duplex(BUFFER_SIZE * 2);
        let task = tokio::spawn(async move {
            stream_pattern_with_delay(&mut writer, 1024, 1, 17)
                .await
                .unwrap()
        });
        let stats = read_pattern(&mut reader, 1024).await.unwrap();
        assert_eq!(stats.bytes, 1024);
        assert_eq!(stats, task.await.unwrap());
    }

    fn stream_hash(bytes: &[u8]) -> u64 {
        bytes.iter().fold(FNV_OFFSET, |hash, byte| {
            (hash ^ *byte as u64).wrapping_mul(FNV_PRIME)
        })
    }
}
