use crate::common::utils::get_remaining_length;
use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use tokio_util::codec::Decoder;

pub struct SubscribePacket {
    pub packet_id: u16,
    pub topics: Vec<Subscription>,
}

pub struct Subscription {
    pub topic: String,
    pub qos: u8,
}

pub struct SubscribeCodec;

impl SubscribeCodec {
    pub fn new() -> Self {
        SubscribeCodec
    }
}

impl Decoder for SubscribeCodec {
    type Item = SubscribePacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.8.1 Fixed Header
        // Reserved bits must be set to 0, 0, 1, 0 respectively or return "malformed packet error"
        let reserved = buf[0] & 0b00001111;
        if reserved != 0b0010 {
            return Err(Error::new(InvalidData, "Malformed remaining length"));
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

        // Advance fixed header byte and remaining length bytes
        // FIXME: Consider advancing until the end
        //buf.advance(1 + consumed_rl_bytes);

        // Skip the fixed header length to read variable header and payload data
        let mut packet_reader = &buf[header_len..total_len];

        // 3.8.2 Variable header
        // Buffer must have 2 bytes to obtain packet id
        if packet_reader.remaining() < 2 {
            return Err(Error::new(
                InvalidData,
                "Protocol violation, subscribe must include packet id",
            ));
        }
        // Contains 2 bytes indicating the packet id
        let packet_id = packet_reader.get_u16();

        // 3.8.3 Payload
        let mut topics = Vec::new();
        // Must contain payload or return "protocol violation error"
        while packet_reader.has_remaining() {
            // 2 (packet_id) + 2 (topics length)
            if packet_reader.remaining() < 2 {
                return Err(Error::new(
                    InvalidData,
                    "Protocol violation, packet must include topic length",
                ));
            }
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

            // Must at least contain one topic filter and qos pair
            if !packet_reader.has_remaining() {
                return Err(Error::new(InvalidData, "Missing Requested QoS"));
            }

            let qos = packet_reader.get_u8();
            // If qos is not 0, 1, 2 must return "malformed packet error"
            if qos > 2 {
                return Err(Error::new(InvalidData, "Invalid QoS level"));
            }
            // TODO: If reserved bits in payload packet are non-zero must return "malformed packet error"

            topics.push(Subscription { topic, qos })
        }

        buf.advance(total_len);

        return Ok(Some(SubscribePacket { packet_id, topics }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_subscribe_packet() {
        // Construct a SUBSCRIBE packet buffer
        let mut buf = BytesMut::new();

        // Fixed Header
        // Byte 1: Control Packet Type (8 for SUBSCRIBE) and flags (0b0010)
        buf.put_u8(0x82);

        // Remaining Length (Variable Byte Integer)
        // Remaining Length is 41 bytes (calculated previously)
        // For Remaining Length <= 127, it's encoded in one byte
        buf.put_u8(41);

        // Variable Header
        // Packet Identifier
        buf.put_u16(10); // Packet Identifier is 10

        // Payload
        // First Topic Filter: "sensor/temperature", QoS 1
        buf.put_u16(18); // Topic Filter Length
        buf.extend_from_slice(b"sensor/temperature"); // Topic Filter
        buf.put_u8(1); // Requested QoS

        // Second Topic Filter: "sensor/humidity", QoS 0
        buf.put_u16(15); // Topic Filter Length
        buf.extend_from_slice(b"sensor/humidity"); // Topic Filter
        buf.put_u8(0); // Requested QoS

        // Initialize the decoder
        let mut codec = SubscribeCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        // Check that the packet is a SUBSCRIBE packet and has the correct values
        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.packet_id, 10);
                assert_eq!(packet.topics.len(), 2);

                // First Subscription
                assert_eq!(packet.topics[0].topic, "sensor/temperature");
                assert_eq!(packet.topics[0].qos, 1);

                // Second Subscription
                assert_eq!(packet.topics[1].topic, "sensor/humidity");
                assert_eq!(packet.topics[1].qos, 0);
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding SUBSCRIBE packet: {:?}", e),
        }
    }
}
