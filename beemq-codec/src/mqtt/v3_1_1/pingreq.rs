use bytes::{Buf, BytesMut};
use std::io::Error;
use tokio_util::codec::Decoder;

pub struct PingreqPacket;

pub struct PingreqCodec;

impl PingreqCodec {
    pub fn new() -> Self {
        PingreqCodec
    }
}

impl Decoder for PingreqCodec {
    type Item = PingreqPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.12.1 Fixed header (no remaining length value)
        // TODO: Validate flags and remainin length to be zero
        // 3.12.2 Variable header (no variable header)
        // 3.12.3 Payload (no payload)
        buf.advance(2);
        Ok(Some(PingreqPacket))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_pingreq_packet() {
        // Construct a PINGREQ packet
        let mut buf = BytesMut::new();
        buf.put_u8(0xC0); // Packet Type (12) << 4 | Flags (0x00)
        buf.put_u8(0x00); // Remaining Length (0 bytes)
        let mut codec = PingreqCodec::new();
        let result = codec.decode(&mut buf);
        match result {
            Ok(Some(PingreqPacket)) => {
                // Successfully decoded PINGREQ packet
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PINGREQ packet: {:?}", e),
        }
    }
}
