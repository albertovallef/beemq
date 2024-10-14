use crate::common::utils::get_remaining_length;
use bytes::{Buf, BufMut, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use tokio_util::codec::Decoder;

pub struct UnsubackPacket {
    pub packet_id: u16,
}

pub struct UnsubackCodec;

impl UnsubackCodec {
    pub fn new() -> Self {
        UnsubackCodec
    }
}

impl Decoder for UnsubackCodec {
    type Item = UnsubackPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.11.1 Fixed header
        // Decode the remaining length
        let (remaining_length, consumed_rl_bytes);
        // Start position is byte 1 since byte 0 is the fixed header
        if let Some((rl, consumed)) = get_remaining_length(buf, 1)? {
            remaining_length = rl;
            consumed_rl_bytes = consumed;
        } else {
            // The entire remaining length is not in buffer
            return Ok(None);
        }

        // Ensure the entire packet is in buffer
        let header_len = 1 + consumed_rl_bytes;

        let total_len = header_len + remaining_length as usize;
        if buf.len() < total_len {
            return Ok(None);
        }

        // Skip the fixed header length to read variable header and payload data
        let mut packet_reader = &buf[header_len..total_len];

        // 3.11.2 Variable header
        // Decode the packet id
        // Buffer must have 2 bytes to obtain packet id
        if packet_reader.remaining() < 2 {
            return Err(Error::new(
                InvalidData,
                "Protocol violation, subscribe must include packet id",
            ));
        }
        // Contains 2 bytes indicating the packet id
        let packet_id = packet_reader.get_u16();

        // 3.11.3 Payload (no payload)
        buf.advance(total_len);
        Ok(Some(UnsubackPacket { packet_id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_unsuback_packet() {
        // Construct an UNSUBACK packet
        let mut buf = BytesMut::new();
        buf.put_u8(0xB0); // Packet Type (11) << 4 | Flags (0x00)
        buf.put_u8(0x02); // Remaining Length (2 bytes for Packet Identifier)
        buf.put_u16(0x1234); // Packet Identifier
        let mut codec = UnsubackCodec::new();
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.packet_id, 0x1234);
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding UNSUBACK packet: {:?}", e),
        }
    }
}
