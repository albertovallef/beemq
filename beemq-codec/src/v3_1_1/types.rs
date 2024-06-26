use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use std::{u16, u32, usize};
use tokio_util::codec::Decoder;

fn get_remaining_length(buf: &mut BytesMut) -> Result<Option<u32>, Error> {
    // 2.2.3 Remaining Length
    let mut multiplier: u32 = 1;
    let mut remaining_length: u32 = 0;
    // Remaining length start at second byte
    let mut pos = 1;

    loop {
        if pos >= buf.len() {
            // Not enough data arrived yet to decode
            return Ok(None);
        }

        let encoded_byte = buf[pos];
        pos += 1;
        remaining_length += (encoded_byte & 127) as u32 * multiplier;
        // Multiply since is the next byte
        multiplier *= 128;

        if multiplier > 128 * 128 * 128 {
            return Err(Error::new(InvalidData, "Malformed remaining length"));
        }

        // MSB is the continuation flag
        if (encoded_byte & 128) == 0 {
            break;
        }
    }
    Ok(Some(remaining_length))
}

fn combine_bytes(msb: u8, lsb: u8) -> u16 {
    ((msb as u16) << 8) | (lsb as u16)
}

pub struct ConnectFlags {
    username_flag: bool,
    password_flag: bool,
    will_retain: bool,
    will_qos: u8,
    will_flag: bool,
    clean_session: bool,
    // reserved bit
}

pub struct ConnectVariable {
    protocol_name: String,
    protocol_level: u8,
    connect_flags: ConnectFlags,
    keep_alive: u16,
}

pub struct ConnectPayload {
    client_id: String,
    will_topic: Option<String>,
    will_message: Option<Vec<u8>>,
    username: Option<String>,
    password: Option<String>,
}

pub struct ConnectPacket {
    variable_header: ConnectVariable,
    payload: ConnectPayload,
}

pub struct ConnectCodec;

impl Decoder for ConnectCodec {
    type Item = ConnectPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Moved on from fixed header
        buf.advance(2);

        // 3.1.2 Variable header
        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);

        // 3.1.2.1 Protocol Name
        let protocol_name_bytes = &buf[..byte_len];
        let protocol_name = match String::from_utf8(protocol_name_bytes.to_vec()) {
            Ok(s) => s.to_string(),
            Err(_e) => return Err(Error::new(InvalidData, "Invalid UTF-8 sequence")),
        };

        if protocol_name != "MQTT" {
            return Err(Error::new(InvalidData, "Invalid protocol name"));
        }

        buf.advance(byte_len);

        // 3.1.2.2 Protocol Level
        let protocol_level = match buf[0] {
            0x04 => buf[0],
            _ => return Err(Error::new(InvalidData, "Invalid protocol level")),
        };
        buf.advance(1);

        // 3.1.2.3 Connect Flags
        let connect_flags = buf[0];
        // Reserved is unused and must be zero
        let reserved = (connect_flags & 0b00000001) != 0;
        if reserved != false {
            return Err(Error::new(InvalidData, "Violated reserved bit zero state"));
        }
        let clean_session = (connect_flags & 0b00000010) != 0;
        let will_flag = (connect_flags & 0b00000100) != 0;

        let will_qos_lsb = (connect_flags & 0b00001000) >> 3;
        let will_qos_msb = (connect_flags & 0b00010000) >> 4;
        let will_qos = (will_qos_msb << 1) | will_qos_lsb;
        if will_qos > 2 {
            return Err(Error::new(InvalidData, "Invalid will qos, greater than 2"));
        }

        let will_retain = (connect_flags & 0b00100000) != 0;
        let password_flag = (connect_flags & 0b01000000) != 0;
        let username_flag = (connect_flags & 0b10000000) != 0;

        let connect_flags = ConnectFlags {
            username_flag,
            password_flag,
            will_retain,
            will_qos,
            will_flag,
            clean_session,
        };
        buf.advance(1);

        // 3.1.2.10 Keep Alive
        // TODO: Must not exceed 18hrs 12 mins and 15 sec
        let keep_alive = combine_bytes(buf[0], buf[1]);
        let variable_header = ConnectVariable {
            protocol_name,
            protocol_level,
            connect_flags,
            keep_alive,
        };
        buf.advance(2);

        // 3.1.3 Payload
        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);
        let client_id_bytes = &buf[..byte_len];
        let client_id = match String::from_utf8(client_id_bytes.to_vec()) {
            Ok(s) => s,
            Err(_e) => return Err(Error::new(InvalidData, "Client id is not UTF-8 encoded")),
        };
        buf.advance(byte_len);

        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);
        let will_topic_bytes = &buf[..byte_len];
        let will_topic = match String::from_utf8(will_topic_bytes.to_vec()) {
            Ok(s) => Some(s),
            Err(_e) => return Err(Error::new(InvalidData, "Will topic is not UTF-8 encoded")),
        };
        buf.advance(byte_len);

        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);
        let will_message = Some(&buf[..byte_len].to_vec()).cloned();
        buf.advance(byte_len);

        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);
        let username_bytes = &buf[..byte_len];
        let username = match String::from_utf8(username_bytes.to_vec()) {
            Ok(s) => Some(s),
            Err(_e) => return Err(Error::new(InvalidData, "Username is not UTF-8 encoded")),
        };
        buf.advance(byte_len);

        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);
        let password_bytes = &buf[..byte_len];
        let password = match String::from_utf8(password_bytes.to_vec()) {
            Ok(s) => Some(s),
            Err(_e) => return Err(Error::new(InvalidData, "Password is not UTF-8 encoded")),
        };
        buf.advance(byte_len);

        let payload = ConnectPayload {
            client_id,
            will_topic,
            will_message,
            username,
            password,
        };

        Ok(Some(ConnectPacket {
            variable_header,
            payload,
        }))
    }
}

pub struct ConnackVariable {
    session_present_flag: bool,
    connect_return_code: u8,
}

pub struct ConnackPacket {
    variable_header: ConnackVariable,
    // No fixed header
}

pub struct ConnackCodec;

impl Decoder for ConnackCodec {
    type Item = ConnackPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Moved on from fixed header
        buf.advance(2);

        // 3.2.2.1 Connect Acknowledge Flags
        let session_present_byte = buf[0];
        let mask: u8 = 0b1111_1110;
        if session_present_byte & mask != 0 {
            return Err(Error::new(InvalidData, "Bits 7-1 must be zero"));
        }
        let session_present_flag = (session_present_byte & 0b00000001) != 0;
        buf.advance(1);

        // 3.2.2.3 Return Code
        let connect_return_code = buf[0];
        buf.advance(1);
        let variable_header = ConnackVariable {
            session_present_flag,
            connect_return_code,
        };
        Ok(Some(ConnackPacket { variable_header }))
    }
}

pub struct PublishPayload;
pub struct PublishVariable;
pub struct PublishPacket;
pub struct PublishCodec;

impl Decoder for PublishCodec {
    type Item = PublishPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.3.1 Fixed header
        let publish_flags = buf[0];
        let dup_flag = (publish_flags & 0b00000001) != 0;
        let retain = (publish_flags & 0b00000010) != 0;
        let temp_buf = publish_flags << 5;
        let qos_val = temp_buf >> 6;

        // FIXME: modify once QoS enum is implemented
        match qos_val {
            0 => (),
            1 => (),
            2 => (),
            _ => {
                return Err(Error::new(
                    InvalidData,
                    "Publish packet must not have both QoS set to 1",
                ))
            }
        }
        // Moved on from fixed header
        buf.advance(2);

        // 3.3.2 Variable header
        let byte_len = combine_bytes(buf[0], buf[1]) as usize;
        buf.advance(2);

        // 3.
        let topic_bytes = &buf[..byte_len];
        let topic = match String::from_utf8(topic_bytes.to_vec()) {
            Ok(s) => s.to_string(),
            Err(_e) => return Err(Error::new(InvalidData, "Invalid UTF-8 sequence")),
        };

        let packet_id = combine_bytes(buf[0], buf[1]);

        Ok(None)
    }
}

pub enum MqttPacket {
    Connect(ConnectPacket),
    Connack(ConnackPacket),
    Publish(PublishPacket),
    //Puback(PubackPacket),
    //Pubrec(PubrecPacket),
    //Pubrel(PubrelPacket),
    //Pubcomp(PubcompPacket),
    //Subscribe(SubscribePacket),
    //Suback(SubackPacket),
    //Unsubscribe(UnsubscribePacket),
    //Unsuback(UnsubackPacket),
    //Pingreq(PingreqPacket),
    //Pingresp(PingrespPacket),
    //Disconnect(DisconnectPacket),
}

pub struct MqttCodec;

impl MqttCodec {
    pub fn new() -> Self {
        Self
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

        let remaining_length = get_remaining_length(buf)?;

        match remaining_length {
            // Ensure the entire packet is in buffer
            Some(rl) => {
                if buf.len() < (1 + rl) as usize {
                    return Ok(None);
                }
            }
            // The entire remaining length is not in buffer
            None => return Ok(None),
        }

        let packet = match packet_type {
            1 => ConnectCodec.decode(buf)?.map(MqttPacket::Connect),
            2 => ConnackCodec.decode(buf)?.map(MqttPacket::Connack),
            3 => PublishCodec.decode(buf)?.map(MqttPacket::Publish),
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
    use bytes::BytesMut;

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
}
