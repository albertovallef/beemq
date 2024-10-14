use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use tokio_util::codec::Decoder;

pub struct ConnackVariable {
    pub session_present_flag: bool,
    pub connect_return_code: u8,
}

pub struct ConnackPacket {
    pub variable_header: ConnackVariable,
    // No fixed header
}

pub struct ConnackCodec;

impl ConnackCodec {
    pub fn new() -> Self {
        ConnackCodec
    }
}

impl Decoder for ConnackCodec {
    type Item = ConnackPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Moved on from fixed header
        buf.advance(2);

        // 3.2.2.1 Connect Acknowledge Flags
        let session_present_byte = buf[0];
        let mask: u8 = 0b1111_1110;
        if session_present_byte & mask != 0 {
            return Err(Error::new(InvalidData, "Bits 7-1 must be zero"));
        }
        let session_present_flag = (session_present_byte & 0b00000001) != 0;
        buf.advance(1);

        // 3.2.2.3 Return Code
        let connect_return_code = buf[0];
        buf.advance(1);
        let variable_header = ConnackVariable {
            session_present_flag,
            connect_return_code,
        };
        Ok(Some(ConnackPacket { variable_header }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_connack_packet() {
        let mut buf = BytesMut::from(
            &[
                0x20, // Packet type (CONNACK) and flags
                0x02, // Remaining length
                0x00, // Connect Acknowledge Flags
                0x00, // Connect Return Code (0 = Connection Accepted)
            ][..],
        );

        let mut codec = ConnackCodec::new();
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.variable_header.session_present_flag, false);
                assert_eq!(packet.variable_header.connect_return_code, 0);
            }
            _ => (),
        }
    }
}
