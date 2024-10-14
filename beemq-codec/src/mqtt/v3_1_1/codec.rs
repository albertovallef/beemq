use crate::common::utils::get_remaining_length;
use crate::mqtt::v3_1_1::connack::{ConnackCodec, ConnackPacket};
use crate::mqtt::v3_1_1::connect::{ConnectCodec, ConnectPacket};
use crate::mqtt::v3_1_1::disconnect::{DisconnectCodec, DisconnectPacket};
use crate::mqtt::v3_1_1::pingreq::{PingreqCodec, PingreqPacket};
use crate::mqtt::v3_1_1::pingresp::{PingrespCodec, PingrespPacket};
use crate::mqtt::v3_1_1::puback::{PubackCodec, PubackPacket};
use crate::mqtt::v3_1_1::pubcomp::{PubcompCodec, PubcompPacket};
use crate::mqtt::v3_1_1::publish::{PublishCodec, PublishPacket};
use crate::mqtt::v3_1_1::pubrec::{PubrecCodec, PubrecPacket};
use crate::mqtt::v3_1_1::pubrel::{PubrelCodec, PubrelPacket};
use crate::mqtt::v3_1_1::suback::{QoSLevel, SubackCodec, SubackPacket, SubscribeReturnCode};
use crate::mqtt::v3_1_1::subscribe::{SubscribeCodec, SubscribePacket};
use crate::mqtt::v3_1_1::unsuback::{UnsubackCodec, UnsubackPacket};
use crate::mqtt::v3_1_1::unsubscribe::{UnsubscribeCodec, UnsubscribePacket};
use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use std::{u16, u32, usize};
use tokio_util::codec::Decoder;

pub enum MqttPacket {
    Connect(ConnectPacket),
    Connack(ConnackPacket),
    Publish(PublishPacket),
    Puback(PubackPacket),
    Pubrec(PubrecPacket),
    Pubrel(PubrelPacket),
    Pubcomp(PubcompPacket),
    Subscribe(SubscribePacket),
    Suback(SubackPacket),
    Unsubscribe(UnsubscribePacket),
    Unsuback(UnsubackPacket),
    Pingreq(PingreqPacket),
    Pingresp(PingrespPacket),
    Disconnect(DisconnectPacket),
}

pub struct MqttCodec;

impl MqttCodec {
    pub fn new() -> Self {
        MqttCodec
    }
}

impl Decoder for MqttCodec {
    type Item = MqttPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 2.2 Fixed Header
        if buf.len() < 2 {
            // Fixed header is 2 bytes. See section 2.2
            return Ok(None); // Wait for entire message to arrive
        }

        // The 4 MSB represent the "packet type"
        // Use shift-right to skip "reserved" bits
        let packet_type = buf[0] >> 4;
        if packet_type < 1 || packet_type > 14 {
            buf.advance(1);
            return Err(Error::new(InvalidData, "Invalid packet type"));
        }

        // TODO: Move remaining length operation to corresponding codecs
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

        let packet = match packet_type {
            1 => ConnectCodec.decode(buf)?.map(MqttPacket::Connect),
            2 => ConnackCodec.decode(buf)?.map(MqttPacket::Connack),
            3 => PublishCodec.decode(buf)?.map(MqttPacket::Publish),
            4 => PubackCodec.decode(buf)?.map(MqttPacket::Puback),
            5 => PubrecCodec.decode(buf)?.map(MqttPacket::Pubrec),
            6 => PubrelCodec.decode(buf)?.map(MqttPacket::Pubrel),
            7 => PubcompCodec.decode(buf)?.map(MqttPacket::Pubcomp),
            8 => SubscribeCodec.decode(buf)?.map(MqttPacket::Subscribe),
            9 => SubackCodec.decode(buf)?.map(MqttPacket::Suback),
            10 => UnsubscribeCodec.decode(buf)?.map(MqttPacket::Unsubscribe),
            10 => UnsubackCodec.decode(buf)?.map(MqttPacket::Unsuback),
            11 => PingreqCodec.decode(buf)?.map(MqttPacket::Pingreq),
            13 => PingrespCodec.decode(buf)?.map(MqttPacket::Pingresp),
            14 => DisconnectCodec.decode(buf)?.map(MqttPacket::Disconnect),
            _ => return Err(Error::new(InvalidData, "Malformed remaining length")),
        };

        let packet = match packet {
            Some(p) => p,
            None => return Ok(None),
        };
        Ok(Some(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_decode_connect_packet() {
        let mut buf = BytesMut::from(
            &[
                0x10, // Packet type for connect
                0x26, // Remaining length
                0x00, 0x04, b'M', b'Q', b'T', b'T', // Protocol name
                0x04, // Protocol level
                0xC6, // Connect Flags (clean session, will flag, username, password)
                0x00, 0x3C, // Keep alive
                0x00, 0x09, b'c', b'l', b'i', b'e', b'n', b't', b'1', b'2',
                b'3', // Client ID "client123"
                0x00, 0x0A, b'w', b'i', b'l', b'l', b'/', b't', b'o', b'p', b'i',
                b'c', // Will Topic "will/topic"
                0x00, 0x0C, b'W', b'i', b'l', b'l', b' ', b'M', b'e', b's', b's', b'a', b'g',
                b'e', // Will Message "Will Message"
                0x00, 0x04, b'u', b's', b'e', b'r', // Username "user"
                0x00, 0x04, b'p', b'a', b's', b's', // Password "pass"
            ][..],
        );

        let mut codec = MqttCodec::new();
        let packet = codec.decode(&mut buf).unwrap().unwrap();

        match packet {
            MqttPacket::Connect(c) => {
                assert_eq!(c.variable_header.protocol_name, String::from("MQTT"));
                assert_eq!(c.variable_header.protocol_level, 0x4);
                assert_eq!(c.variable_header.connect_flags.username_flag, true);
                assert_eq!(c.variable_header.connect_flags.password_flag, true);
                assert_eq!(c.variable_header.connect_flags.will_retain, false);
                assert_eq!(c.variable_header.connect_flags.will_qos, 0);
                assert_eq!(c.variable_header.connect_flags.clean_session, true);
                assert_eq!(c.variable_header.keep_alive, 60);
                assert_eq!(c.variable_header.connect_flags.password_flag, true);
                assert_eq!(c.payload.client_id, String::from("client123"));
                match c.payload.will_topic {
                    Some(t) => assert_eq!(t, String::from("will/topic")),
                    _ => (),
                }
                //assert_eq!(c.payload.will_message, String::from("Will Message"));
                match c.payload.username {
                    Some(u) => assert_eq!(u, String::from("user")),
                    _ => (),
                }
                match c.payload.password {
                    Some(p) => assert_eq!(p, String::from("pass")),
                    _ => (),
                }
            }
            _ => (),
        }
    }

    #[test]
    fn test_decode_connack_packet() {
        let mut buf = BytesMut::from(
            &[
                0x20, // Packet type (CONNACK) and flags
                0x02, // Remaining length
                0x00, // Connect Acknowledge Flags
                0x00, // Connect Return Code (0 = Connection Accepted)
            ][..],
        );

        let mut codec = MqttCodec::new();
        let packet = codec.decode(&mut buf).unwrap().unwrap();
        match packet {
            MqttPacket::Connack(c) => {
                assert_eq!(c.variable_header.session_present_flag, false);
                assert_eq!(c.variable_header.connect_return_code, 0);
            }
            _ => (),
        }
    }

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

        let mut codec = MqttCodec::new();
        let packet = codec.decode(&mut buf).unwrap().unwrap();
        match packet {
            MqttPacket::Publish(p) => {
                assert_eq!(p.dup_flag, false);
                assert_eq!(p.qos, 1);
                assert_eq!(p.retain, false);
                assert_eq!(p.topic, String::from("test"));
                assert_eq!(p.packet_id, Some(10));
                assert_eq!(p.payload, b"Hello".to_vec());
            }
            _ => panic!("Expected a PUBLISH packet"),
        }
    }

    #[test]
    fn test_decode_puback_packet() {
        // Construct a buffer representing a PUBREC packet
        let mut buf = BytesMut::new();
        // Fixed Header
        buf.put_u8(0x40); // Packet type (4 for PUBACK)
        buf.put_u8(0x02); // Remaining Length is 2 (for the Packet Identifier)

        // Variable Header
        buf.put_u16(13); // Packet identifier (e.g, 10)

        let mut codec = MqttCodec::new();
        let packet = codec.decode(&mut buf).unwrap().unwrap();
        match packet {
            MqttPacket::Puback(p) => {
                assert_eq!(p.packet_id, 13);
            }
            _ => panic!("Expected a PUBACK packet"),
        }
    }

    #[test]
    fn test_decode_pubrec_packet() {
        // Construct a buffer representing a PUBREC packet
        let mut buf = BytesMut::new();
        // Fixed Header
        buf.put_u8(0x50); // Packet type (5 for PUBREC)
        buf.put_u8(0x02); // Remaining Length is 2 (for the Packet Identifier)

        // Variable Header
        buf.put_u16(10); // Packet identifier (e.g, 10)

        let mut codec = MqttCodec::new();
        let packet = codec.decode(&mut buf).unwrap().unwrap();
        match packet {
            MqttPacket::Pubrec(p) => {
                assert_eq!(p.packet_id, 10);
            }
            _ => panic!("Expected a PUBREC packet"),
        }
    }

    #[test]
    fn test_decode_pubrel_packet() {
        // Construct a buffer representing a PUBREL packet
        let mut buf = BytesMut::new();
        // Fixed Header
        buf.put_u8(0x60); // Packet type (6 for PUBREL)
        buf.put_u8(0x02); // Remaining Length is 2 (for the Packet Identifier)

        // Variable Header
        buf.put_u16(200); // Packet identifier (e.g, 200)

        let mut codec = MqttCodec::new();
        let packet = codec.decode(&mut buf).unwrap().unwrap();
        match packet {
            MqttPacket::Pubrel(p) => {
                assert_eq!(p.packet_id, 200);
            }
            _ => panic!("Expected a PUBREL packet"),
        }
    }

    #[test]
    fn test_decode_pubcomp_packet() {
        let mut buf = BytesMut::new();
        // Fixed Header
        buf.put_u8(0x70);
        buf.put_u8(0x02);

        // Variable Header
        buf.put_u16(100);

        let mut codec = MqttCodec::new();
        let packet = codec.decode(&mut buf).unwrap().unwrap();
        match packet {
            MqttPacket::Pubcomp(p) => {
                assert_eq!(p.packet_id, 100);
            }
            _ => panic!("Expected a PUBCOMP packet"),
        }
    }

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
        let mut codec = MqttCodec::new();

        // Decode the packet
        let packet = codec.decode(&mut buf).unwrap().unwrap();

        // Check that the packet is a SUBSCRIBE packet and has the correct values
        match packet {
            MqttPacket::Subscribe(p) => {
                assert_eq!(p.packet_id, 10);
                assert_eq!(p.topics.len(), 2);

                // First Subscription
                assert_eq!(p.topics[0].topic, "sensor/temperature");
                assert_eq!(p.topics[0].qos, 1);

                // Second Subscription
                assert_eq!(p.topics[1].topic, "sensor/humidity");
                assert_eq!(p.topics[1].qos, 0);
            }
            _ => panic!("Expected a SUBSCRIBE packet"),
        }
    }

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
        let mut codec = MqttCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(MqttPacket::Suback(packet))) => {
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
            Ok(Some(_)) => panic!("Expected SUBACK packet"),
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding SUBACK packet: {:?}", e),
        }
    }

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
        let mut codec = MqttCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(MqttPacket::Unsubscribe(packet))) => {
                assert_eq!(packet.packet_id, 0x1234);
                assert_eq!(
                    packet.topics,
                    vec![
                        "sensor/temperature".to_string(),
                        "sensor/humidity".to_string()
                    ]
                );
            }
            Ok(Some(_)) => panic!("Expected UNSUBSCRIBE packet"),
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding UNSUBSCRIBE packet: {:?}", e),
        }
    }

    #[test]
    fn test_decode_unsuback_packet() {
        // Construct an UNSUBACK packet
        let mut buf = BytesMut::new();

        // Fixed Header
        buf.put_u8(0xB0); // Packet Type (11) << 4 | Flags (0x00)

        // Remaining Length
        buf.put_u8(0x02); // Remaining Length (2 bytes for Packet Identifier)

        // Variable Header: Packet Identifier
        buf.put_u16(0x1234); // Packet Identifier

        // Initialize the decoder
        let mut codec = MqttCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(MqttPacket::Unsuback(packet))) => {
                assert_eq!(packet.packet_id, 0x1234);
            }
            Ok(Some(_)) => panic!("Expected UNSUBACK packet"),
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding UNSUBACK packet: {:?}", e),
        }
    }

    #[test]
    fn test_decode_pingreq_packet() {
        // Construct a PINGREQ packet
        let mut buf = BytesMut::new();

        // Fixed Header
        buf.put_u8(0xC0); // Packet Type (12) << 4 | Flags (0x00)

        // Remaining Length
        buf.put_u8(0x00); // Remaining Length (0 bytes)

        // Initialize the decoder
        let mut codec = MqttCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(MqttPacket::Pingreq(_packet))) => {
                // Successfully decoded PINGREQ packet
            }
            Ok(Some(_)) => panic!("Expected PINGREQ packet"),
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PINGREQ packet: {:?}", e),
        }
    }

    #[test]
    fn test_decode_pingresp_packet() {
        // Construct a PINGRESP packet
        let mut buf = BytesMut::new();

        // Fixed Header
        buf.put_u8(0xD0); // Packet Type (13) << 4 | Flags (0x00)

        // Remaining Length
        buf.put_u8(0x00); // Remaining Length (0 bytes)

        // Initialize the decoder
        let mut codec = MqttCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(MqttPacket::Pingresp(_packet))) => {
                // Successfully decoded PINGRESP packet
            }
            Ok(Some(_)) => panic!("Expected PINGRESP packet"),
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding PINGRESP packet: {:?}", e),
        }
    }

    #[test]
    fn test_decode_disconnect_packet() {
        // Construct a DISCONNECT packet
        let mut buf = BytesMut::new();

        // Fixed Header
        buf.put_u8(0xE0); // Packet Type (14) << 4 | Flags (0x00)

        // Remaining Length
        buf.put_u8(0x00); // Remaining Length (0 bytes)

        // Initialize the decoder
        let mut codec = MqttCodec::new();

        // Decode the packet
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(MqttPacket::Disconnect(_packet))) => {
                // Successfully decoded DISCONNECT packet
            }
            Ok(Some(_)) => panic!("Expected DISCONNECT packet"),
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding DISCONNECT packet: {:?}", e),
        }
    }
}
