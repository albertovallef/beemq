use bytes::{Buf, BytesMut};
use std::io;
use tokio_util::codec::Decoder;

pub struct FixedHeader {
    packet_type: u8,
    remaining_length: u32,
}

pub struct FixedHeaderCodec;

impl FixedHeaderCodec {
    pub fn new() -> Self {
        Self
    }
}

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

impl Decoder for ConnectCodec {
    type Item = ConnectPacket;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // TODO: Investigate what to do with these 2 bytes
        buf.advance(2);
        // Section 3.1.2.1
        let protocl_name_bytes = &buf[..4];
        // TODO: Return error if protocol name is incorrect
        let protocol_name = String::from_utf8(protocl_name_bytes.to_vec()).unwrap();

        if protocol_name != "MQTT" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incorrect protocol name",
            ));
        }

        buf.advance(4);
        // Section 3.1.2.2
        let protocol_level = buf[0];
        match protocol_level {
            0x04 => (),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incorrect protocol level",
                ))
            }
        };
        buf.advance(1);

        let connect_flags = buf[0];
        // Reserved bit must be zero or error
        let reserved = (connect_flags & 0b00000001) != 0;
        if reserved != false {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Violated reserved bit state",
            ));
        }
        let clean_session = (connect_flags & 0b00000010) != 0;
        let will_flag = (connect_flags & 0b00000100) != 0;

        let will_qos_bit_1 = (connect_flags & 0b00001000) >> 3;
        let will_qos_bit_2 = (connect_flags & 0b00010000) >> 4;
        let will_qos = (will_qos_bit_2 << 1) | will_qos_bit_1;

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

        // Section 3.1.2.10
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
        let client_id_msb = buf[0];
        let client_id_lsb = buf[1];
        // TODO: Must not exceed 18hrs 12 mins and 15 sec
        let client_id_bit_len = ((client_id_msb as usize) << 8) | (client_id_lsb as usize);
        buf.advance(2);
        let client_id_bytes = &buf[..client_id_bit_len];
        let client_id = String::from_utf8(client_id_bytes.to_vec()).unwrap();
        buf.advance(client_id_bit_len as usize);

        let will_topic_msb = buf[0];
        let will_topic_lsb = buf[1];
        // TODO: Must not exceed 18hrs 12 mins and 15 sec
        let will_topic_bit_len = ((will_topic_msb as usize) << 8) | (will_topic_lsb as usize);
        buf.advance(2);
        let will_topic_bytes = &buf[..will_topic_bit_len];
        let will_topic = Some(String::from_utf8(will_topic_bytes.to_vec()).unwrap());
        buf.advance(will_topic_bit_len);

        let will_message_msb = buf[0];
        let will_message_lsb = buf[1];
        let will_message_bit_len = ((will_message_msb as usize) << 8) | (will_message_lsb as usize);
        buf.advance(2);
        let will_message = Some(&buf[..will_message_bit_len].to_vec()).cloned();
        buf.advance(will_message_bit_len);

        let username_msb = buf[0];
        let username_lsb = buf[1];
        let username_bit_len = ((username_msb as usize) << 8) | (username_lsb as usize);
        buf.advance(2);
        let username_bytes = &buf[..username_bit_len];
        let username = Some(String::from_utf8(username_bytes.to_vec()).unwrap());
        buf.advance(username_bit_len);

        let password_msb = buf[0];
        let password_lsb = buf[1];
        let password_bit_len = ((password_msb as usize) << 8) | (password_lsb as usize);
        buf.advance(2);
        let password_bytes = &buf[..password_bit_len];
        let password = Some(String::from_utf8(password_bytes.to_vec()).unwrap());
        buf.advance(password_bit_len);

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
        let mut fh_codec = FixedHeaderCodec::new();

        let fixed_header = fh_codec.decode(buf)?;

        let fixed_header = match fixed_header {
            Some(header) => header,
            None => return Ok(None),
        };

        if buf.len() < (1 + fixed_header.remaining_length).try_into().unwrap() {
            Ok(None)
        } else {
            buf.advance(1);
            buf.advance(1);

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

        //// Skip fixed header bytes
        //if buf.len() < (1 + fixed_header.remaining_length).try_into().unwrap() {
        // Ok(None)
        //}
        //
        //buf.advance(1);
        //buf.advance(1);

        // let packet = match fixed_header.packet_type {
        //     1 => ConnectDecoder.decode(buf),
        //     _ => Err(io::Error::new(
        //         io::ErrorKind::InvalidData,
        //         "Unknown packet type",
        //     )),
        // };
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

        //assert_eq!(
        //    packet,
        //    MqttPacket::Connect(ConnectPacket {
        //        fixed_header: FixedHeader {
        //            packet_type: 1,
        //            flags: 2,
        //            remaining_length: 2,
        //        },
        //        variable_header: ConnectVariable {
        //            protocol_name: "MQTT".to_string(),
        //            protocol_level: 4,
        //            connect_flags: 2,
        //            keep_alive: 60,
        //        },
        //        payload: ConnectPayload {
        //            client_id: "Alberto".to_string(),
        //            will_topic: "api/v1".to_string(),
        //            will_message: 2,
        //            user_name: "Alberto".to_string(),
        //            password: "pass".to_string(),
        //        }
        //    })
        //);
    }
}
