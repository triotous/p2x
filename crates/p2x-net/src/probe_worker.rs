use crate::probe::{
    MAX_HEADER, MAX_TRANSFER, ProbeAck, ProbeError, ProbeHeader, ProbeMode, ProbePath,
    ProbeTerminal, SCHEMA_VERSION, decode_header, pattern_byte,
};
use futures::io::{
    AsyncRead as FuturesRead, AsyncReadExt as FuturesReadExt, AsyncWrite as FuturesWrite,
    AsyncWriteExt as FuturesWriteExt,
};
use libp2p::PeerId;
use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};

pub const BUFFER_SIZE: usize = 32 * 1024;
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_WORKERS: usize = 128;
pub const MAX_WORKERS_PER_PEER: usize = 64;
const FNV_OFFSET: u64 = 1469598103934665603;
const FNV_PRIME: u64 = 1099511628211;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamStats {
    pub bytes: u64,
    pub hash: u64,
}

#[derive(Debug, Default)]
pub struct WorkerAdmission {
    global: usize,
    per_peer: HashMap<PeerId, usize>,
    closed: bool,
}

impl WorkerAdmission {
    pub fn admit(&mut self, peer: PeerId) -> Result<(), ProbeError> {
        let peer_count = self.per_peer.get(&peer).copied().unwrap_or(0);
        if self.closed || self.global >= MAX_WORKERS || peer_count >= MAX_WORKERS_PER_PEER {
            return Err(ProbeError::AdmissionRejected);
        }
        self.global += 1;
        self.per_peer.insert(peer, peer_count + 1);
        Ok(())
    }

    pub fn release(&mut self, peer: PeerId) -> bool {
        let Some(peer_count) = self.per_peer.get_mut(&peer) else {
            return false;
        };
        self.global -= 1;
        *peer_count -= 1;
        if *peer_count == 0 {
            self.per_peer.remove(&peer);
        }
        true
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    pub const fn admitted(&self) -> usize {
        self.global
    }
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

pub async fn read_pattern_futures<R: FuturesRead + Unpin>(
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
        let count = remaining.min(BUFFER_SIZE as u64) as usize;
        reader.read_exact(&mut buffer[..count]).await?;
        for byte in &buffer[..count] {
            hash = (hash ^ *byte as u64).wrapping_mul(FNV_PRIME);
        }
        remaining -= count as u64;
        bytes += count as u64;
    }
    Ok(StreamStats { bytes, hash })
}

pub async fn read_pattern_futures_with_delay<R: FuturesRead + Unpin>(
    reader: &mut R,
    length: u64,
    delay_ms: u32,
    requested_chunk: u32,
) -> io::Result<StreamStats> {
    if length > MAX_TRANSFER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transfer exceeds configured limit",
        ));
    }
    let chunk = if requested_chunk == 0 {
        BUFFER_SIZE
    } else {
        requested_chunk as usize
    };
    if chunk > BUFFER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunk exceeds buffer limit",
        ));
    }
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut offset = 0;
    let mut hash = FNV_OFFSET;
    while offset < length {
        let count = (length - offset).min(chunk as u64) as usize;
        reader.read_exact(&mut buffer[..count]).await?;
        for byte in &buffer[..count] {
            hash = (hash ^ *byte as u64).wrapping_mul(FNV_PRIME);
        }
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

async fn expect_eof_futures<R: FuturesRead + Unpin>(reader: &mut R) -> Result<(), ProbeError> {
    let mut byte = [0u8; 1];
    match reader.read(&mut byte).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(ProbeError::EofMismatch),
        Err(error) => Err(ProbeError::Io(error.to_string())),
    }
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
        let ack = ProbeAck {
            schema_version: SCHEMA_VERSION,
            nonce: header.nonce,
            request_id: header.request_id,
            path: ProbePath::Relay,
            connection_id_hash: 0,
            bytes_read: 0,
            bytes_written: 0,
            read_hash: 0,
            write_hash: 0,
            half_close: false,
            terminal: ProbeTerminal::Ok,
        };
        let body =
            serde_json::to_vec(&ack).map_err(|error| ProbeError::Invalid(error.to_string()))?;
        write_frame_async(writer, &body).await?;
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

pub async fn send_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &ProbeHeader,
) -> Result<(), ProbeError> {
    let body =
        serde_json::to_vec(header).map_err(|error| ProbeError::Invalid(error.to_string()))?;
    write_frame_async(writer, &body).await
}

pub async fn read_ack<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ProbeAck, ProbeError> {
    let body = timeout(WORKER_TIMEOUT, read_frame_async(reader))
        .await
        .map_err(|_| ProbeError::Timeout)??;
    serde_json::from_slice(&body).map_err(|error| ProbeError::Invalid(error.to_string()))
}

pub async fn write_frame_futures<W: FuturesWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), ProbeError> {
    if body.len() > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    writer
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|_| ProbeError::Truncated)?;
    writer
        .write_all(body)
        .await
        .map_err(|_| ProbeError::Truncated)
}

pub async fn read_frame_futures<R: FuturesRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ProbeError> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(|_| ProbeError::Truncated)?;
    let length = u32::from_be_bytes(prefix) as usize;
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

pub async fn execute_probe_futures<S>(
    stream: &mut S,
    path: ProbePath,
    connection_id_hash: u64,
) -> Result<ProbeAck, ProbeError>
where
    S: FuturesRead + FuturesWrite + Unpin,
{
    execute_probe_futures_with_timeout(stream, path, connection_id_hash, WORKER_TIMEOUT).await
}

pub async fn execute_probe_futures_with_timeout<S>(
    stream: &mut S,
    path: ProbePath,
    connection_id_hash: u64,
    deadline: Duration,
) -> Result<ProbeAck, ProbeError>
where
    S: FuturesRead + FuturesWrite + Unpin,
{
    timeout(
        deadline,
        execute_probe_server_inner(stream, path, connection_id_hash),
    )
    .await
    .map_err(|_| ProbeError::Timeout)?
}

async fn execute_probe_server_inner<S>(
    stream: &mut S,
    path: ProbePath,
    connection_id_hash: u64,
) -> Result<ProbeAck, ProbeError>
where
    S: FuturesRead + FuturesWrite + Unpin,
{
    let body = read_frame_futures(stream).await?;
    let header = decode_header(&body)?;
    let read = match header.mode {
        ProbeMode::NonceEcho => StreamStats { bytes: 0, hash: 0 },
        ProbeMode::HalfClose => {
            let stats = read_pattern_futures(stream, header.length)
                .await
                .map_err(|error| ProbeError::Io(error.to_string()))?;
            if stats.hash != crate::probe::pattern_hash(header.length) {
                return Err(ProbeError::HashMismatch);
            }
            expect_eof_futures(stream).await?;
            stats
        }
        ProbeMode::SlowReader => read_pattern_futures_with_delay(
            stream,
            header.length,
            header.slow_delay_ms,
            header.slow_chunk_size,
        )
        .await
        .map_err(|error| ProbeError::Io(error.to_string()))?,
    };
    if header.mode == ProbeMode::SlowReader
        && read.hash != crate::probe::pattern_hash(header.length)
    {
        return Err(ProbeError::HashMismatch);
    }
    let written = match header.mode {
        ProbeMode::NonceEcho => StreamStats { bytes: 0, hash: 0 },
        ProbeMode::HalfClose | ProbeMode::SlowReader => {
            stream_pattern_futures(stream, header.length, 0, 0)
                .await
                .map_err(|error| ProbeError::Io(error.to_string()))?
        }
    };
    let ack = ProbeAck {
        schema_version: SCHEMA_VERSION,
        nonce: header.nonce,
        request_id: header.request_id,
        path,
        connection_id_hash,
        bytes_read: read.bytes,
        bytes_written: written.bytes,
        read_hash: read.hash,
        write_hash: written.hash,
        half_close: header.mode == ProbeMode::HalfClose,
        terminal: ProbeTerminal::Ok,
    };
    let encoded =
        serde_json::to_vec(&ack).map_err(|error| ProbeError::Invalid(error.to_string()))?;
    write_frame_futures(stream, &encoded).await?;
    if header.mode == ProbeMode::HalfClose {
        stream.close().await.map_err(|_| ProbeError::Truncated)?;
    }
    Ok(ack)
}

pub async fn execute_probe_client_futures<S>(
    stream: &mut S,
    header: &ProbeHeader,
) -> Result<ProbeAck, ProbeError>
where
    S: FuturesRead + FuturesWrite + Unpin,
{
    execute_probe_client_futures_with_timeout(stream, header, WORKER_TIMEOUT).await
}

pub async fn execute_probe_client_futures_with_timeout<S>(
    stream: &mut S,
    header: &ProbeHeader,
    deadline: Duration,
) -> Result<ProbeAck, ProbeError>
where
    S: FuturesRead + FuturesWrite + Unpin,
{
    timeout(deadline, execute_probe_client_inner(stream, header))
        .await
        .map_err(|_| ProbeError::Timeout)?
}

async fn execute_probe_client_inner<S>(
    stream: &mut S,
    header: &ProbeHeader,
) -> Result<ProbeAck, ProbeError>
where
    S: FuturesRead + FuturesWrite + Unpin,
{
    let encoded =
        serde_json::to_vec(header).map_err(|error| ProbeError::Invalid(error.to_string()))?;
    // Decode locally too so callers cannot bypass the same closed validation used by the server.
    decode_header(&encoded)?;
    write_frame_futures(stream, &encoded).await?;
    let sent = match header.mode {
        ProbeMode::NonceEcho => StreamStats { bytes: 0, hash: 0 },
        ProbeMode::HalfClose | ProbeMode::SlowReader => {
            stream_pattern_futures(stream, header.length, 0, 0)
                .await
                .map_err(|error| ProbeError::Io(error.to_string()))?
        }
    };
    if header.mode == ProbeMode::HalfClose {
        stream
            .close()
            .await
            .map_err(|error| ProbeError::Io(error.to_string()))?;
    } else {
        stream
            .flush()
            .await
            .map_err(|error| ProbeError::Io(error.to_string()))?;
    }
    let received = match header.mode {
        ProbeMode::NonceEcho => StreamStats { bytes: 0, hash: 0 },
        ProbeMode::HalfClose | ProbeMode::SlowReader => read_pattern_futures(stream, header.length)
            .await
            .map_err(|error| ProbeError::Io(error.to_string()))?,
    };
    if received.hash != sent.hash || received.bytes != sent.bytes {
        return Err(ProbeError::HashMismatch);
    }
    let ack_body = read_frame_futures(stream).await?;
    let ack: ProbeAck = serde_json::from_slice(&ack_body)
        .map_err(|error| ProbeError::Invalid(error.to_string()))?;
    if ack.schema_version != SCHEMA_VERSION
        || ack.request_id != header.request_id
        || ack.nonce != header.nonce
        || ack.bytes_read != sent.bytes
        || ack.read_hash != sent.hash
        || ack.bytes_written != received.bytes
        || ack.write_hash != received.hash
        || ack.half_close != (header.mode == ProbeMode::HalfClose)
        || ack.terminal != ProbeTerminal::Ok
    {
        return Err(ProbeError::HashMismatch);
    }
    if header.mode == ProbeMode::HalfClose {
        expect_eof_futures(stream).await?;
    }
    Ok(ack)
}

pub async fn stream_pattern_futures<W: FuturesWrite + Unpin>(
    writer: &mut W,
    length: u64,
    delay_ms: u32,
    requested_chunk: u32,
) -> io::Result<StreamStats> {
    if length > MAX_TRANSFER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transfer exceeds configured limit",
        ));
    }
    let chunk = if requested_chunk == 0 {
        BUFFER_SIZE
    } else {
        requested_chunk as usize
    };
    if chunk > BUFFER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunk exceeds buffer limit",
        ));
    }
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut offset = 0;
    let mut hash = FNV_OFFSET;
    while offset < length {
        let count = (length - offset).min(chunk as u64) as usize;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{ProbeHeader, SCHEMA_VERSION, pattern_hash, write_frame};
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

    #[tokio::test]
    async fn futures_worker_streams_slow_reader_payload() {
        let mut output = futures::io::Cursor::new(Vec::new());
        let stats = stream_pattern_futures(&mut output, 1024, 0, 17)
            .await
            .unwrap();
        assert_eq!(stats.bytes, 1024);
        assert_eq!(stats.hash, stream_hash(output.get_ref()));
        assert_eq!(output.get_ref()[251], 0);
    }

    #[tokio::test]
    async fn server_observes_half_close_and_reports_both_directions() {
        let header = ProbeHeader {
            schema_version: SCHEMA_VERSION,
            request_id: 7,
            mode: ProbeMode::HalfClose,
            nonce: 9,
            length: 257,
            slow_delay_ms: 0,
            slow_chunk_size: 0,
        };
        let mut input = Vec::new();
        write_frame(&mut input, &serde_json::to_vec(&header).unwrap()).unwrap();
        input.extend((0..header.length).map(pattern_byte));
        let request_len = input.len();
        let mut stream = futures::io::Cursor::new(input);
        let ack = execute_probe_futures(&mut stream, ProbePath::Direct, 11)
            .await
            .unwrap();
        assert_eq!(ack.bytes_read, header.length);
        assert_eq!(ack.bytes_written, header.length);
        assert_eq!(ack.read_hash, pattern_hash(header.length));
        assert_eq!(ack.write_hash, pattern_hash(header.length));
        assert!(ack.half_close);
        assert_eq!(
            &stream.get_ref()[request_len..request_len + header.length as usize],
            &(0..header.length).map(pattern_byte).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn server_rejects_wrong_pattern_and_trailing_half_close_bytes() {
        let header = ProbeHeader {
            schema_version: SCHEMA_VERSION,
            request_id: 1,
            mode: ProbeMode::HalfClose,
            nonce: 1,
            length: 1,
            slow_delay_ms: 0,
            slow_chunk_size: 0,
        };
        let encoded = serde_json::to_vec(&header).unwrap();
        let mut wrong = Vec::new();
        write_frame(&mut wrong, &encoded).unwrap();
        wrong.push(99);
        assert_eq!(
            execute_probe_futures(&mut futures::io::Cursor::new(wrong), ProbePath::Relay, 1).await,
            Err(ProbeError::HashMismatch)
        );

        let mut trailing = Vec::new();
        write_frame(&mut trailing, &encoded).unwrap();
        trailing.extend([pattern_byte(0), 99]);
        assert_eq!(
            execute_probe_futures(&mut futures::io::Cursor::new(trailing), ProbePath::Relay, 1)
                .await,
            Err(ProbeError::EofMismatch)
        );
    }

    #[test]
    fn worker_admission_enforces_global_and_per_peer_limits() {
        let first = PeerId::random();
        let second = PeerId::random();
        let mut admission = WorkerAdmission::default();
        for _ in 0..MAX_WORKERS_PER_PEER {
            admission.admit(first).unwrap();
        }
        assert_eq!(admission.admit(first), Err(ProbeError::AdmissionRejected));
        for _ in 0..MAX_WORKERS_PER_PEER {
            admission.admit(second).unwrap();
        }
        assert_eq!(admission.admitted(), MAX_WORKERS);
        assert_eq!(
            admission.admit(PeerId::random()),
            Err(ProbeError::AdmissionRejected)
        );
        assert!(admission.release(first));
        assert!(!admission.release(PeerId::random()));
        admission.close();
        assert_eq!(admission.admit(first), Err(ProbeError::AdmissionRejected));
    }

    fn stream_hash(bytes: &[u8]) -> u64 {
        bytes.iter().fold(FNV_OFFSET, |hash, byte| {
            (hash ^ *byte as u64).wrapping_mul(FNV_PRIME)
        })
    }
}
