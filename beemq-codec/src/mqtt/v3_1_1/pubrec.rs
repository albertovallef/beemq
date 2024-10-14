use crate::common::utils::combine_bytes;
use bytes::{Buf, BytesMut};
use std::io::Error;
use tokio_util::codec::Decoder;

pub struct PubrecPacket {
    pub packet_id: u16,
}

pub struct PubrecCodec;

impl PubrecCodec {
    pub fn new() -> Self {
        PubrecCodec
    }
}

impl Decoder for PubrecCodec {
    type Item = PubrecPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // FIXME: Validate reserved bits
        // Moved on from fixed header
        buf.advance(2);

        let packet_id = combine_bytes(buf[0], buf[1]);
        buf.advance(2);
        Ok(Some(PubrecPacket { packet_id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_pubrec_packet() {
        // Construct a buffer representing a PUBREC packet
        let mut buf = BytesMut::new();
        // Fixed Header
        buf.put_u8(0x50); // Packet type (5 for PUBREC)
        buf.put_u8(0x02); // Remaining Length is 2 (for the Packet Identifier)

        // Variable Header
        buf.put_u16(10); // Packet identifier (e.g, 10)

        let mut codec = PubrecCodec::new();
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.packet_id, 10);
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PUBREC packet: {:?}", e),
        }
    }
}
