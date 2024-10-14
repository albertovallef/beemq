use bytes::{Buf, BufMut, BytesMut};
use std::io::{Error, ErrorKind};
use tokio_util::codec::{Decoder, Encoder};

pub struct DisconnectPacket;

pub struct DisconnectCodec;

impl DisconnectCodec {
    pub fn new() -> Self {
        DisconnectCodec
    }
}

impl Decoder for DisconnectCodec {
    type Item = DisconnectPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 2 bytes for fixed header
        if buf.len() < 2 {
            return Ok(None);
        }

        let fixed_header = buf[0];
        let remaining_length = buf[1];

        // Validate that packet type is DISCONNECT (0xE0) and flags are zero
        if fixed_header != 0xE0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid packet type for DISCONNECT",
            ));
        }

        // Validate that remaining length is zero
        if remaining_length != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Remaining length must be zero in DISCONNECT packet",
            ));
        }

        buf.advance(2);
        Ok(Some(DisconnectPacket))
    }
}

impl Encoder<DisconnectPacket> for DisconnectCodec {
    type Error = Error;

    fn encode(&mut self, _item: DisconnectPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Encode the fixed header for DISCONNECT packet
        dst.put_u8(0xE0); // Packet type for DISCONNECT with flags zeroed
        dst.put_u8(0x00); // Remaining length is zero
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_disconnect_packet() {
        // Construct a DISCONNECT packet
        let mut buf = BytesMut::new();
        buf.put_u8(0xE0); // Packet Type (14) << 4 | Flags (0x00)
        buf.put_u8(0x00); // Remaining Length (0 bytes)
        let mut codec = DisconnectCodec::new();
        let result = codec.decode(&mut buf);
        match result {
            Ok(Some(DisconnectPacket)) => {
                // Successfully decoded DISCONNECT packet
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding DISCONNECT packet: {:?}", e),
        }
    }
}
