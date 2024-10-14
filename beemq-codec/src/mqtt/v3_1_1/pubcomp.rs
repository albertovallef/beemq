use crate::common::utils::combine_bytes;
use bytes::{Buf, BytesMut};
use std::io::Error;
use tokio_util::codec::Decoder;

pub struct PubcompPacket {
    pub packet_id: u16,
}

pub struct PubcompCodec;

impl PubcompCodec {
    pub fn new() -> Self {
        PubcompCodec
    }
}

impl Decoder for PubcompCodec {
    type Item = PubcompPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // FIXME: Validate reserved bits
        // Moved on from fixed header
        buf.advance(2);

        let packet_id = combine_bytes(buf[0], buf[1]);
        buf.advance(2);
        Ok(Some(PubcompPacket { packet_id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_pubcomp_packet() {
        let mut buf = BytesMut::new();
        // Fixed Header
        buf.put_u8(0x70);
        buf.put_u8(0x02);

        // Variable Header
        buf.put_u16(100);

        let mut codec = PubcompCodec::new();
        let result = codec.decode(&mut buf);
        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.packet_id, 100);
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PUBCOMP packet: {:?}", e),
        }
    }
}
