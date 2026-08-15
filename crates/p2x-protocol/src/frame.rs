use std::io::{self, Read, Write};
pub const MAX_AUTH_FRAME: usize = 4096;
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_AUTH_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body)?;
    Ok(body)
}
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_AUTH_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid frame length",
        ));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds() {
        let mut out = Vec::new();
        assert!(write_frame(&mut out, &[]).is_err());
        assert!(write_frame(&mut out, &[1; MAX_AUTH_FRAME + 1]).is_err());
        assert_eq!(
            read_frame(&mut &[0, 0, 0, 0][..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
