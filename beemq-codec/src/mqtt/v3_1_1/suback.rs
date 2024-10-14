use crate::common::utils::get_remaining_length;
use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use tokio_util::codec::Decoder;

#[derive(Debug, PartialEq)]
pub enum SubscribeReturnCode {
    Success(QoSLevel),
    Failure,
}

#[derive(Debug, PartialEq)]
pub enum QoSLevel {
    AtMostOnce = 0x00,
    AtLeastOnce = 0x01,
    ExactlyOnce = 0x02,
}

#[derive(Debug, PartialEq)]
pub struct SubackPacket {
    pub packet_id: u16,
    pub return_codes: Vec<SubscribeReturnCode>,
}

#[derive(Debug, PartialEq)]
pub struct SubackCodec;

impl SubackCodec {
    pub fn new() -> Self {
        SubackCodec
    }
}

impl Decoder for SubackCodec {
    type Item = SubackPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.9.1 Fixed Header
        let reserved = buf[0] & 0b00001111;
        if reserved != 0b0000 {
            return Err(Error::new(InvalidData, "Malformed packet"));
        }

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

        // 3.9.2 Variable header
        // Buffer must have 2 bytes to obtain packet id
        if packet_reader.remaining() < 2 {
            return Err(Error::new(
                InvalidData,
                "Protocol violation, subscribe must include packet id",
            ));
        }
        // Contains 2 bytes indicating the packet id
        let packet_id = packet_reader.get_u16();

        let mut return_codes = Vec::new();

        while packet_reader.has_remaining() {
            let code = packet_reader.get_u8();
            let return_code = match code {
                0x00 => SubscribeReturnCode::Success(QoSLevel::AtMostOnce),
                0x01 => SubscribeReturnCode::Success(QoSLevel::AtLeastOnce),
                0x02 => SubscribeReturnCode::Success(QoSLevel::ExactlyOnce),
                0x80 => SubscribeReturnCode::Failure,
                _ => return Err(Error::new(InvalidData, "Invalid return code in suback")),
            };
            return_codes.push(return_code)
        }

        buf.advance(total_len);

        Ok(Some(SubackPacket {
            packet_id,
            return_codes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_suback_packet() {
        // Construct a SUBACK packet
        let mut buf = BytesMut::new();

        // Fixed Header
        buf.put_u8(0x90); // Packet Type (9) << 4 | Flags (0)

        // Remaining Length
        // Variable Header (2 bytes) + Payload (3 Return Codes)
        let remaining_length = 2 + 3; // 5 bytes
        buf.put_u8(remaining_length as u8);

        // Variable Header: Packet Identifier
        buf.put_u16(0x1234); // Packet Identifier (e.g., 4660 in decimal)

        // Payload: Return Codes
        buf.put_u8(0x00); // Success - Maximum QoS 0
        buf.put_u8(0x01); // Success - Maximum QoS 1
        buf.put_u8(0x80); // Failure

        // Initialize the decoder
        let mut codec = SubackCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.packet_id, 0x1234);
                assert_eq!(
                    packet.return_codes,
                    vec![
                        SubscribeReturnCode::Success(QoSLevel::AtMostOnce),
                        SubscribeReturnCode::Success(QoSLevel::AtLeastOnce),
                        SubscribeReturnCode::Failure,
                    ]
                );
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding SUBACK packet: {:?}", e),
        }
    }
}
