use bytes::{Buf, BytesMut};
use std::io;
use tokio_util::codec::Decoder;

pub struct FixedHeader {
    packet_type: u8,
    remaining_length: u32,
}

pub struct FixedHeaderCodec;

impl Decoder for FixedHeaderCodec {
    type Item = FixedHeader;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() < 2 {
            // Fixed header is 2 bytes. See section 2.2
            return Ok(None); // Wait for entire message to arrive
        }

        // The 4 LSB are "reserved" (unused bits)
        // The 4 MSG are the "packet type"
        // Use shift-right to skip "reserved" bits
        let packet_type = buf[0] >> 4;
        if packet_type < 1 || packet_type > 14 {
            buf.advance(1);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid packet type",
            ));
        }

        // Remaining length Algorithm. See section 2.2.3
        let mut multiplier: u32 = 1;
        let mut remaining_length: u32 = 0;
        let mut pos = 1; // remaining length start at second byte

        loop {
            if pos >= buf.len() {
                return Ok(None); // Not enough data arrived yet
            }

            let encoded_byte = buf[pos];
            pos += 1;
            remaining_length += (encoded_byte & 127) as u32 * multiplier;
            // Multiply since is the next byte
            multiplier *= 128;

            if multiplier > 128 * 128 * 128 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Malformed remaining length",
                ));
            }

            // MSB is the continuation flag
            if (encoded_byte & 128) == 0 {
                break;
            }
        }

        Ok(Some(FixedHeader {
            packet_type,
            remaining_length,
        }))
    }
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

impl ConnectCodec {
    fn get_bytes_len(&mut self, msb: u8, lsb: u8) -> usize {
        // Get the number of bytes to read from byte sequence
        // given MSB and LSB
        let byte_len = ((msb as usize) << 8) | (lsb as usize);
        byte_len
    }
}

impl Decoder for ConnectCodec {
    type Item = ConnectPacket;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.1.2 Variable header
        let byte_len = self.get_bytes_len(buf[0], buf[1]);
        buf.advance(2);

        // 3.1.2.1 Protocol Name
        let protocl_name_bytes = &buf[..byte_len];
        let protocol_name = match String::from_utf8(protocl_name_bytes.to_vec()) {
            Ok(s) => s.to_string(),
            Err(_e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid UTF-8 sequence",
                ))
            }
        };

        if protocol_name != "MQTT" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid protocol name",
            ));
        }

        buf.advance(byte_len);

        // 3.1.2.2 Protocol Level
        let protocol_level = match buf[0] {
            0x04 => buf[0],
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid protocol level",
                ))
            }
        };
        buf.advance(1);

        // 3.1.2.3 Connect Flags
        let connect_flags = buf[0];
        // Reserved is unused and must be zero
        let reserved = (connect_flags & 0b00000001) != 0;
        if reserved != false {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Violated reserved bit zero state",
            ));
        }
        let clean_session = (connect_flags & 0b00000010) != 0;
        let will_flag = (connect_flags & 0b00000100) != 0;

        let will_qos_lsb = (connect_flags & 0b00001000) >> 3;
        let will_qos_msb = (connect_flags & 0b00010000) >> 4;
        let will_qos = (will_qos_msb << 1) | will_qos_lsb;
        if will_qos > 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid will qos, greater than 2",
            ));
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
        let keep_alive_msb = buf[0];
        let keep_alive_lsb = buf[1];
        // TODO: Must not exceed 18hrs 12 mins and 15 sec
        let keep_alive = ((keep_alive_msb as u16) << 8) | (keep_alive_lsb as u16);
        let variable_header = ConnectVariable {
            protocol_name,
            protocol_level,
            connect_flags,
            keep_alive,
        };
        buf.advance(2);

        // 3.1.3 Payload
        let byte_len = self.get_bytes_len(buf[0], buf[1]);
        buf.advance(2);
        let client_id_bytes = &buf[..byte_len];
        let client_id = match String::from_utf8(client_id_bytes.to_vec()) {
            Ok(s) => s,
            Err(_e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Client id is not UTF-8 encoded",
                ))
            }
        };
        buf.advance(byte_len);

        let byte_len = self.get_bytes_len(buf[0], buf[1]);
        buf.advance(2);
        let will_topic_bytes = &buf[..byte_len];
        let will_topic = match String::from_utf8(will_topic_bytes.to_vec()) {
            Ok(s) => Some(s),
            Err(_e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Will topic is not UTF-8 encoded",
                ))
            }
        };
        buf.advance(byte_len);

        let byte_len = self.get_bytes_len(buf[0], buf[1]);
        buf.advance(2);
        let will_message = Some(&buf[..byte_len].to_vec()).cloned();
        buf.advance(byte_len);

        let byte_len = self.get_bytes_len(buf[0], buf[1]);
        buf.advance(2);
        let username_bytes = &buf[..byte_len];
        let username = match String::from_utf8(username_bytes.to_vec()) {
            Ok(s) => Some(s),
            Err(_e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Username is not UTF-8 encoded",
                ))
            }
        };
        buf.advance(byte_len);

        let byte_len = self.get_bytes_len(buf[0], buf[1]);
        buf.advance(2);
        let password_bytes = &buf[..byte_len];
        let password = match String::from_utf8(password_bytes.to_vec()) {
            Ok(s) => Some(s),
            Err(_e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Password is not UTF-8 encoded",
                ))
            }
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

pub enum MqttPacket {
    Connect(ConnectPacket),
    // Continue adding definitions
}

pub struct MqttCodec;

impl MqttCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for MqttCodec {
    type Item = ConnectPacket;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Read leading 4 bits to get packet type
        let fixed_header = FixedHeaderCodec.decode(buf)?;

        let fixed_header = match fixed_header {
            Some(header) => header,
            None => return Ok(None),
        };

        if buf.len() < (1 + fixed_header.remaining_length).try_into().unwrap() {
            Ok(None)
        } else {
            buf.advance(2);

            let packet = match fixed_header.packet_type {
                1 => ConnectCodec.decode(buf).unwrap(),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Malformed remaining length",
                    ))
                }
            };

            let packet = match packet {
                Some(packet) => packet,
                None => return Ok(None),
            };

            Ok(Some(packet))
        }
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
        let connect = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(connect.variable_header.protocol_name, String::from("MQTT"));
        assert_eq!(
            connect.payload.will_topic.unwrap(),
            String::from("will/topic")
        );
    }
}
