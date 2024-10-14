use crate::common::utils::combine_bytes;
use bytes::{Buf, BytesMut};
use std::io::Error;
use tokio_util::codec::Decoder;

pub struct PubrelPacket {
    pub packet_id: u16,
}

pub struct PubrelCodec;

impl PubrelCodec {
    pub fn new() -> Self {
        PubrelCodec
    }
}

impl Decoder for PubrelCodec {
    type Item = PubrelPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // FIXME: Validate reserved bits
        // Moved on from fixed header
        buf.advance(2);

        let packet_id = combine_bytes(buf[0], buf[1]);
        buf.advance(2);
        Ok(Some(PubrelPacket { packet_id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_pubrel_packet() {
        // Construct a buffer representing a PUBREL packet
        let mut buf = BytesMut::new();
        // Fixed Header
        buf.put_u8(0x60); // Packet type (6 for PUBREL)
        buf.put_u8(0x02); // Remaining Length is 2 (for the Packet Identifier)

        // Variable Header
        buf.put_u16(200); // Packet identifier (e.g, 200)

        let mut codec = PubrelCodec::new();
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.packet_id, 200);
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PUBREL packet: {:?}", e),
        }
    }
}
