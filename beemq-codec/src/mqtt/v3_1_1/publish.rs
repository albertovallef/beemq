use crate::common::utils::combine_bytes;
use crate::common::utils::get_remaining_length;
use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use tokio_util::codec::Decoder;

pub struct PublishPacket {
    pub dup_flag: bool,
    pub retain: bool,
    pub qos: u8,
    pub topic: String,
    pub packet_id: Option<u16>,
    pub payload: BytesMut,
}

pub struct PublishCodec;

impl PublishCodec {
    pub fn new() -> Self {
        PublishCodec
    }
}

impl Decoder for PublishCodec {
    type Item = PublishPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.3.1 Fixed header
        let publish_flags = buf[0] & 0b00001111; // Extract lower 4 bits
        let dup_flag = (publish_flags & 0b00001000) != 0;
        let retain = (publish_flags & 0b00000001) != 0;
        let qos = (publish_flags & 0b00000110) >> 1;

        // FIXME: modify once QoS enum is implemented
        match qos {
            0 | 1 | 2 => (),
            _ => {
                return Err(Error::new(
                    InvalidData,
                    "Publish packet must not have both QoS set to 1",
                ))
            }
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
        let total_len = 1 + consumed_rl_bytes + remaining_length as usize;
        if buf.len() < total_len {
            return Ok(None);
        }

        // Advance fixed header byte and remaining length bytes
        buf.advance(1 + consumed_rl_bytes);

        // 3.3.2 Variable header
        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);

        // 3.3.2.1 Topic Name
        let topic_bytes = buf.split_to(byte_len); // split_to advances the buffer
        let topic = match std::str::from_utf8(&topic_bytes) {
            Ok(s) => s.to_string(),
            Err(_e) => return Err(Error::new(InvalidData, "Invalid UTF-8 sequence")),
        };

        // 3.3.2.2 Packet Identifier
        let packet_id = if qos > 0 {
            let pid = combine_bytes(buf[0], buf[1]);
            buf.advance(2);
            Some(pid)
        } else {
            None
        };

        // 3.3.4 Payload
        let variable_header_lenght = 2 + byte_len + if qos > 0 { 2 } else { 0 };
        let payload_len = remaining_length as usize - variable_header_lenght;

        let payload = buf.split_to(payload_len);

        Ok(Some(PublishPacket {
            dup_flag,
            retain,
            qos,
            topic,
            packet_id,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_publish_packet() {
        let mut buf = BytesMut::from(
            &[
                0x32, // Fixed header (PUBLISH, QoS 1)
                0x0D, // Corrected Remaining length (13 bytes)
                0x00, 0x04, // Topic name length (4 bytes)
                0x74, 0x65, 0x73, 0x74, // Topic name "test"
                0x00, 0x0A, // Packet identifier (10)
                0x48, 0x65, 0x6C, 0x6C, 0x6F, // Payload "Hello"
            ][..],
        );

        let mut codec = PublishCodec::new();
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.dup_flag, false);
                assert_eq!(packet.qos, 1);
                assert_eq!(packet.retain, false);
                assert_eq!(packet.topic, String::from("test"));
                assert_eq!(packet.packet_id, Some(10));
                assert_eq!(packet.payload, b"Hello".to_vec());
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PUBLISH packet: {:?}", e),
        }
    }
}
