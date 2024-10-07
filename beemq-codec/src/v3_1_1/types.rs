use bytes::{Buf, BytesMut};
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use std::{u16, u32, usize};
use tokio_util::codec::Decoder;

fn get_remaining_length(
    buf: &mut BytesMut,
    start_pos: usize,
) -> Result<Option<(u32, usize)>, Error> {
    // 2.2.3 Remaining Length
    let mut multiplier: u32 = 1;
    let mut remaining_length: u32 = 0;
    // Remaining length start at second byte
    let mut pos = start_pos;

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
    let consumed_bytes = pos - start_pos;
    Ok(Some((remaining_length, consumed_bytes)))
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

pub struct PublishPacket {
    dup_flag: bool,
    retain: bool,
    qos: u8,
    topic: String,
    packet_id: Option<u16>,
    payload: BytesMut,
}

pub struct PublishCodec;

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

pub struct PubackPacket {
    packet_id: u16,
}

pub struct PubackCodec;

impl Decoder for PubackCodec {
    type Item = PubackPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // FIXME: Validate reserved bits
        // Moved on from fixed header
        buf.advance(2);

        let packet_id = combine_bytes(buf[0], buf[1]);
        buf.advance(2);
        Ok(Some(PubackPacket { packet_id }))
    }
}

pub struct PubrecPacket {
    packet_id: u16,
}

pub struct PubrecCodec;

impl Decoder for PubrecCodec {
    type Item = PubrecPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // FIXME: Validate reserved bits
        // Moved on from fixed header
        buf.advance(2);

        let packet_id = combine_bytes(buf[0], buf[1]);
        buf.advance(2);
        Ok(Some(PubrecPacket { packet_id }))
    }
}

pub struct PubrelPacket {
    packet_id: u16,
}

pub struct PubrelCodec;

impl Decoder for PubrelCodec {
    type Item = PubrelPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // FIXME: Validate reserved bits
        // Moved on from fixed header
        buf.advance(2);

        let packet_id = combine_bytes(buf[0], buf[1]);
        buf.advance(2);
        Ok(Some(PubrelPacket { packet_id }))
    }
}

pub struct PubcompPacket {
    packet_id: u16,
}

pub struct PubcompCodec;

impl Decoder for PubcompCodec {
    type Item = PubcompPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // FIXME: Validate reserved bits
        // Moved on from fixed header
        buf.advance(2);

        let packet_id = combine_bytes(buf[0], buf[1]);
        buf.advance(2);
        Ok(Some(PubcompPacket { packet_id }))
    }
}

pub struct SubscribePacket {
    packet_id: u16,
    topics: Vec<Subscription>,
}

pub struct Subscription {
    topic: String,
    qos: u8,
}

pub struct SubscribeCodec;

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

#[derive(Debug, PartialEq)]
pub struct SubackPacket {
    packet_id: u16,
    return_codes: Vec<SubscribeReturnCode>,
}

#[derive(Debug, PartialEq)]
pub struct SubackCodec;

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

pub struct UnsubscribePacket {
    packet_id: u16,
    topics: Vec<String>,
}

pub struct UnsubscribeCodec;

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

pub struct UnsubackPacket {
    packet_id: u16,
}

pub struct UnsubackCodec;

impl Decoder for UnsubackCodec {
    type Item = UnsubackPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.11.1 Fixed header
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

        // 3.11.2 Variable header
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

        // 3.11.3 Payload (no payload)
        buf.advance(total_len);
        Ok(Some(UnsubackPacket { packet_id }))
    }
}

pub struct PingreqPacket;

pub struct PingreqCodec;

impl Decoder for PingreqCodec {
    type Item = PingreqPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.12.1 Fixed header (no remaining length value)
        // TODO: Validate flags and remainin length to be zero
        // 3.12.2 Variable header (no variable header)
        // 3.12.3 Payload (no payload)
        buf.advance(2);
        Ok(Some(PingreqPacket))
    }
}

pub struct PingrespPacket;

pub struct PingrespCodec;

impl Decoder for PingrespCodec {
    type Item = PingrespPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 3.13.1 Fixed header (no remaining length value)
        // TODO: Validate flags and remainin length to be zero
        // 3.13.2 Variable header (no variable header)
        // 3.13.3 Payload (no payload)
        buf.advance(2);
        Ok(Some(PingrespPacket))
    }
}

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
            11 => UnsubackCodec.decode(buf)?.map(MqttPacket::Unsuback),
            12 => PingreqCodec.decode(buf)?.map(MqttPacket::Pingreq),
            13 => PingrespCodec.decode(buf)?.map(MqttPacket::Pingresp),
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
}
