use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;

pub fn get_remaining_length(
    buf: &mut BytesMut,
    start_pos: usize,
) -> Result<Option<(u32, usize)>, Error> {
    // 2.2.3 Remaining Length
    let mut multiplier: u32 = 1;
    let mut remaining_length: u32 = 0;
    // Remaining length start at second byte
    let mut pos = start_pos;

    loop {
        if pos >= buf.len() {
            // Not enough data arrived yet to decode
            return Ok(None);
        }

        let encoded_byte = buf[pos];
        pos += 1;
        remaining_length += (encoded_byte & 127) as u32 * multiplier;
        // Multiply since is the next byte
        multiplier *= 128;

        if multiplier > 128 * 128 * 128 {
            return Err(Error::new(InvalidData, "Malformed remaining length"));
        }

        // MSB is the continuation flag
        if (encoded_byte & 128) == 0 {
            break;
        }
    }
    let consumed_bytes = pos - start_pos;
    Ok(Some((remaining_length, consumed_bytes)))
}

pub fn combine_bytes(msb: u8, lsb: u8) -> u16 {
    ((msb as u16) << 8) | (lsb as u16)
}
