use bytes::{Buf, BufMut, BytesMut};
use std::io::{Error, ErrorKind};
use tokio_util::codec::{Decoder, Encoder};

pub struct PingrespPacket;

pub struct PingrespCodec;

impl PingrespCodec {
    pub fn new() -> Self {
        PingrespCodec
    }
}

impl Decoder for PingrespCodec {
    type Item = PingrespPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.13.1 Fixed header (no remaining length value)
        // TODO: Validate flags and remainin length to be zero
        // 3.13.2 Variable header (no variable header)
        // 3.13.3 Payload (no payload)
        buf.advance(2);
        Ok(Some(PingrespPacket))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_pingresp_packet() {
        // Construct a PINGRESP packet
        let mut buf = BytesMut::new();
        buf.put_u8(0xD0); // Packet Type (13) << 4 | Flags (0x00)
        buf.put_u8(0x00); // Remaining Length (0 bytes)
        let mut codec = PingrespCodec::new();
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(PingrespPacket)) => {
                // Successfully decoded PINGRESP packet
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PINGRESP packet: {:?}", e),
        }
    }
}
