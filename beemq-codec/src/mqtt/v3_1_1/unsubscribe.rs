use crate::common::utils::get_remaining_length;
use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use tokio_util::codec::Decoder;

pub struct UnsubscribePacket {
    pub packet_id: u16,
    pub topics: Vec<String>,
}

pub struct UnsubscribeCodec;

impl UnsubscribeCodec {
    pub fn new() -> Self {
        UnsubscribeCodec
    }
}

impl Decoder for UnsubscribeCodec {
    type Item = UnsubscribePacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.10.1 Fixed header
        // Validate reserved bits are 0, 0, 1, 0 respectively
        let reserved = buf[0] & 0b00001111;
        if reserved != 0b0010 {
            return Err(Error::new(InvalidData, "Malformed packet"));
        }
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

        // 3.10.2 Variable header
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

        // 3.10.3 Payload
        // TODO: Validate that payload must contain at least one topic filter, or return protocol violation
        let mut topics: Vec<String> = Vec::new();
        while packet_reader.has_remaining() {
            let topic_len = packet_reader.get_u16() as usize;
            if packet_reader.remaining() < topic_len {
                return Err(Error::new(
                    InvalidData,
                    "Protocol violation, incomplete topic filter",
                ));
            }
            let topic_bytes = packet_reader.copy_to_bytes(topic_len);
            // Topics must be UTF-8 encoded + wildcards
            let topic = match std::str::from_utf8(&topic_bytes) {
                Ok(s) => s.to_string(),
                Err(_e) => return Err(Error::new(InvalidData, "Invalid UTF-8 sequence")),
            };
            topics.push(topic);
        }

        buf.advance(total_len);
        Ok(Some(UnsubscribePacket { packet_id, topics }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_unsubscribe_packet() {
        // Construct an UNSUBSCRIBE packet
        let mut buf = BytesMut::new();

        // Fixed Header
        buf.put_u8(0xA2); // Packet Type (10) << 4 | Flags (0x02)
                          // Remaining Length
                          // Variable Header (2 bytes) + Payload ()
        let remaining_length = 2 + 2 + 18 + 2 + 15; // 5 bytes
        buf.put_u8(remaining_length as u8);

        // Variable Header: Packet Identifier
        buf.put_u16(0x1234); // Packet Identifier

        // First Topic Filter: "sensor/temperature"
        let topic1 = "sensor/temperature";
        buf.put_u16(topic1.len() as u16); // Length of the topic filter
        buf.extend_from_slice(topic1.as_bytes()); // Topic Filter string

        // Second Topic Filter: "sensor/humidity"
        let topic2 = "sensor/humidity";
        buf.put_u16(topic2.len() as u16); // Length of the topic filter
        buf.extend_from_slice(topic2.as_bytes()); // Topic Filter string
                                                  // Initialize the decoder
        let mut codec = UnsubscribeCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.packet_id, 0x1234);
                assert_eq!(
                    packet.topics,
                    vec![
                        "sensor/temperature".to_string(),
                        "sensor/humidity".to_string()
                    ]
                );
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding UNSUBSCRIBE packet: {:?}", e),
        }
    }
}
