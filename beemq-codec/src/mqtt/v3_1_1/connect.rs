use crate::common::utils::combine_bytes;
use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use tokio_util::codec::Decoder;

pub struct ConnectFlags {
    pub username_flag: bool,
    pub password_flag: bool,
    pub will_retain: bool,
    pub will_qos: u8,
    pub will_flag: bool,
    pub clean_session: bool,
    // reserved bit
}

pub struct ConnectVariable {
    pub protocol_name: String,
    pub protocol_level: u8,
    pub connect_flags: ConnectFlags,
    pub keep_alive: u16,
}

pub struct ConnectPayload {
    pub client_id: String,
    pub will_topic: Option<String>,
    pub will_message: Option<Vec<u8>>,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub struct ConnectPacket {
    pub variable_header: ConnectVariable,
    pub payload: ConnectPayload,
}

pub struct ConnectCodec;

impl ConnectCodec {
    pub fn new() -> Self {
        ConnectCodec
    }
}

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

        let mut codec = ConnectCodec::new();
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(packet)) => {
                assert_eq!(packet.variable_header.protocol_name, String::from("MQTT"));
                assert_eq!(packet.variable_header.protocol_level, 0x4);
                assert_eq!(packet.variable_header.connect_flags.username_flag, true);
                assert_eq!(packet.variable_header.connect_flags.password_flag, true);
                assert_eq!(packet.variable_header.connect_flags.will_retain, false);
                assert_eq!(packet.variable_header.connect_flags.will_qos, 0);
                assert_eq!(packet.variable_header.connect_flags.clean_session, true);
                assert_eq!(packet.variable_header.keep_alive, 60);
                assert_eq!(packet.variable_header.connect_flags.password_flag, true);
                assert_eq!(packet.payload.client_id, String::from("client123"));
                match packet.payload.will_topic {
                    Some(t) => assert_eq!(t, String::from("will/topic")),
                    _ => (),
                }
                //assert_eq!(c.payload.will_message, String::from("Will Message"));
                match packet.payload.username {
                    Some(u) => assert_eq!(u, String::from("user")),
                    _ => (),
                }
                match packet.payload.password {
                    Some(p) => assert_eq!(p, String::from("pass")),
                    _ => (),
                }
            }
            Ok(None) => panic!("Incomplete packet"),
            Err(e) => panic!("Error decoding CONNECT packet: {:?}", e),
        }
    }
}
