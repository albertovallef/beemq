use bytes::BytesMut;
use std::io;
use tokio_util::codec::Decoder;

pub enum MqttPacket {
    Reserved,
    Connect(ConnectPacket),
    // Continue adding definitions
}

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

pub struct ConnectVariable {
    protocol_name: String,
    protocol_level: u8,
    connect_flags: u8,
    keep_alive: u16,
}

pub struct ConnectPayload {
    client_id: String,
    will_topic: Option<String>,
    will_message: Option<u8>,
    user_name: Option<String>,
    password: Option<String>,
}

pub struct ConnectPacket {
    fixed_header: FixedHeader,
    variable_header: ConnectVariable,
    payload: ConnectPayload,
}

//pub struct ConnectDecoder;
//
//impl Decoder for ConnectDecoder {
//    type Item = ConnectPacket;
//    type Error = io::Error;
//
//    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {}
//}

pub struct MqttCodec;

impl MqttCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for MqttCodec {
    type Item = FixedHeader;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Read leading 4 bits to get packet type
        let mut fh_codec = FixedHeaderCodec::new();

        return Ok(fh_codec.decode(buf)?);

        // Ensure buf contains the full packet to decode
        //if buf.len() < 1 + fixed_header.remaining_length {
        //    Ok(None);
        //}

        //// Skip fixed header bytes
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
        let fixed_header = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(fixed_header.packet_type, 1);
        assert_eq!(fixed_header.remaining_length, 38);

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
