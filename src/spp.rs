/*
Author Drake Boulianne 2025 

This module defines the packet structure of the SPP Packet defined by CCSDS 133.0-B-2

*/


use std::io::Read;

/// Indicates the packet type of the SPP packet, only has Telecommand and Telemetry variants
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Telemetry,
    Telecommand
}

impl PacketType {
    fn to_bits(&self) -> u16 {
        match self {
            Self::Telemetry => 0b0,
            Self::Telecommand => 0b1,
        }
    }

    pub fn from_bits(bits: u16) -> Self {
        match bits & 0b1 {
            0b0 => Self::Telemetry,
            0b1 => Self::Telecommand,
            _ => unreachable!()
        }
    }

    /// returns boolean indicating if instance of `PacketType` is `PacketType::Telecommand`
    pub fn is_telecommand(&self) -> bool {
        matches!(self, Self::Telecommand)
    }

    /// returns boolean indicating if instance of `PacketType` is `PacketType::Telemetry`
    pub fn is_telemetry(&self) -> bool {
        matches!(self, Self::Telemetry)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SequenceFlag {
    Continuation,
    Start,
    End,
    Unsegmented,
}

impl SequenceFlag {
    pub fn to_bits(&self) -> u16 {
        match self {
            Self::Continuation => 0b00,
            Self::Start => 0b01,
            Self::End => 0b10,
            Self::Unsegmented => 0b11,
        }
    }

    pub fn from_bits(bits: u16) -> Self {
        match bits & 0b11 {
            0b00 => Self::Continuation,
            0b01 => Self::Start,
            0b10 => Self::End,
            0b11 => Self::Unsegmented,
            _ => unreachable!()
        }
    }

    pub fn is_continuation(&self) -> bool {
        matches!(self, Self::Continuation)
    }

    pub fn is_start(&self) -> bool {
        matches!(self, Self::Start)
    }

    pub fn is_end(&self) -> bool {
        matches!(self, Self::End)
    }
    pub fn is_unsegmented(&self) -> bool {
        matches!(self, Self::Unsegmented)
    }
}

pub struct PrimaryHeader {

    /// Hardcoded to 0b000, but here incase standard changes in the future (3 bits)
    version: u8,

    /// packet type defined by `PacketType` enum (1 bit)
    pub packet_type: PacketType,

    /// Indicates if secondary header is used (1 bit)
    pub secondary_header: bool,

    /// Application process ID of the packet (11 bits)
    pub apid: u16,

    /// segment flag (2 bits)
    pub sequence_flag: SequenceFlag,

    /// Sequence Number (14 bits)
    pub sequence_number: u16,
}

impl PrimaryHeader {
    /// Hardcoded Version number for SPP packet
    pub const VERSION: u8 = 0b000;

    /// Various shift values for Primary Header
    const VERSION_SHIFT: usize = 13;
    const PACKET_TYPE_SHIFT: usize = 12;
    const SECONDARY_HEADER_SHIFT: usize = 11;
    const APID_SHIFT: usize = 0;
    const SEQUENCE_FLAG_SHIFT: usize = 14;

    /// Mask Values for encoding and decoding primary header
    const PACKET_TYPE_MASK: u16 = 0x1000;
    const SECONDARY_HEADER_MASK: u16 = 0x0800;
    const APID_MASK: u16 = 0x03FF;
    const SEQUENCE_FLAG_MASK: u16 = 0xC000;
    const SEQUENCE_NUMBER_MASK: u16 = 0x3FFF;


    pub fn encode(&self) -> Vec<u8> {
        let packet_id =
            u16::from(Self::VERSION) << Self::VERSION_SHIFT |
            self.packet_type.to_bits() << Self::PACKET_TYPE_SHIFT |
            u16::from(self.secondary_header) << Self::SECONDARY_HEADER_SHIFT |
            u16::from(self.apid & Self::APID_MASK) << Self::APID_SHIFT;

        let sequence_ctl =
            self.sequence_flag.to_bits() << Self::SEQUENCE_FLAG_SHIFT |
            u16::from(self.sequence_number) & Self::SEQUENCE_NUMBER_MASK;

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&u16::to_be_bytes(packet_id));
        encoded.extend_from_slice(&u16::to_be_bytes(sequence_ctl));

        encoded
    }

    pub fn decode<R: Read>(buf: &mut R) -> std::io::Result<Self> {
        let mut tmp = [0u8; 4];
        buf.read(&mut tmp)?;

        let packet_id = u16::from_be_bytes([tmp[0], tmp[1]]);
        let sequence_ctl = u16::from_be_bytes([tmp[2], tmp[3]]);

        let (version, packet_type, secondary_header, apid) = (
            (packet_id >> Self::VERSION_SHIFT) as u8,
            PacketType::from_bits((packet_id & Self::PACKET_TYPE_MASK) >> Self::PACKET_TYPE_SHIFT),
            packet_id & Self::SECONDARY_HEADER_MASK != 0,
            packet_id & Self::APID_MASK,
        );
        
        let (sequence_flag, sequence_number) = (
            SequenceFlag::from_bits((sequence_ctl & Self::SEQUENCE_FLAG_MASK) >> Self::SEQUENCE_FLAG_SHIFT),
            sequence_ctl & Self::SEQUENCE_NUMBER_MASK
        );

        Ok(Self {version, packet_type, secondary_header, apid, sequence_flag, sequence_number})
    }

}



#[cfg(test)]
pub mod tests {
    use super::*;
    use rstest::rstest;

    
    #[rstest]
    fn test_primary_header_codec(
        #[values(PacketType::Telecommand, PacketType::Telemetry)]
        packet_type: PacketType,
        #[values(true, false)]
        secondary_header: bool,
        #[values(SequenceFlag::Continuation, SequenceFlag::Start, SequenceFlag::End, SequenceFlag::Unsegmented)]
        sequence_flag: SequenceFlag,


        ) {
        let hdr = PrimaryHeader {
            version: PrimaryHeader::VERSION,
            packet_type,
            secondary_header,
            apid: 0,
            sequence_flag,
            sequence_number: 0
        };
        
        let encoded = hdr.encode();

        let decoded = PrimaryHeader::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.version, hdr.version);
        assert_eq!(decoded.packet_type, hdr.packet_type);
        assert_eq!(decoded.secondary_header, hdr.secondary_header);
        assert_eq!(decoded.apid, hdr.apid);
        assert_eq!(decoded.sequence_flag, hdr.sequence_flag);
        assert_eq!(decoded.sequence_number, hdr.sequence_number);
    }

}



