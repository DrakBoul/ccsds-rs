//! Provides functionality to create, encode, and decode Space Packet Protocol
//! packets specified by the CCSDS 133.0-B-2 June 2020 Standard.
//!
//! General Usage:
//! ``` rust
//! use ccsds::spp::{SpacePacket, PacketType, SequenceFlag};
//!
//! # fn main() {
//!     // Define user specified data.
//!     let my_payload = "Hello, world!".as_bytes().to_vec();
//!
//!     // Generate SpacePacket
//!     let my_space_packet = SpacePacket::new(
//!         PacketType::Telecommand,
//!         false,
//!         67,
//!         SequenceFlag::Unsegmented,
//!         0,
//!         my_payload // User data (includes secondary header if used)
//!     );
//!
//!     // Encode SpacePacket as vector of bytes for transmission
//!     let encoded = my_space_packet.encode();
//!
//!     // Do something with space packet....
//!
//!     // Decoding a space packet.
//!     let decoded = SpacePacket::decode(&mut encoded.as_slice())
//!     .expect("Failed to decode SpacePacket!");
//! # }
//!
//! ```

use std::io::Read;

/// SPP Packet as defined by the CCSDS 133.0-B-2 Standard.
pub struct SpacePacket {
    pub primary_header: PrimaryHeader,
    pub payload: Vec<u8>
}

impl SpacePacket {
    pub fn new(
        packet_type: PacketType, 
        secondary_header: bool,
        apid: u16,
        sequence_flag: SequenceFlag,
        sequence_number: u16,
        payload: Vec<u8>
    ) -> Self {
        assert!(payload.len() <= u16::MAX as usize);
        assert!(apid <= PrimaryHeader::APID_MASK);
        assert!(sequence_number <= PrimaryHeader::SEQUENCE_NUMBER_MASK);

        let primary_header = PrimaryHeader {
            version: PrimaryHeader::VERSION,
            packet_type,
            secondary_header,
            apid,
            sequence_flag,
            sequence_number,
        };

        Self { primary_header, payload }
    }

    /// Encodes the [SpacePacket] as a vector of bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = self.primary_header.encode();
        // Subtract 1 from user data field as specified in CCSDS 133.0-B-2 Standard
        encoded.extend_from_slice(&u16::to_be_bytes((self.payload.len() - 1) as u16));
        encoded.extend_from_slice(&self.payload);
        encoded

    }
    
    /// Decodes the primary header from a source that implements [Read]. Returns the result of the
    /// operation, on success giving the decoded [SpacePacket].
    pub fn decode<R: Read>(buf: &mut R) -> std::io::Result<Self> {
        let primary_header = PrimaryHeader::decode(buf)?;
        
        let mut tmp = [0u8; 2];
        buf.read_exact(&mut tmp)?;
        // Add single byte back to payload length that we subtracted during encoding
        let payload_len = u16::from_be_bytes(tmp) + 1;

        let mut payload = vec![0u8; payload_len as usize];
        buf.read_exact(&mut payload)?;

        Ok(Self { primary_header, payload })
    }
}


/// Indicates if the SPP packet is of the Telemetry or Telecommand types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Telemetry = 0,
    Telecommand = 1,
}

impl PacketType {
    /// Converts the [PacketType] enum into its bitwise representation to be used in the SPP
    /// primary header.
    pub fn to_bits(&self) -> u16 {
        match self {
            Self::Telemetry => 0b0,
            Self::Telecommand => 0b1,
        }
    }
    
    /// Converts the raw bits (after being shifted) from the packet ID portion of the primary
    /// header into [PacketType].
    pub fn from_bits(bits: u16) -> Self {
        match bits & 0b1 {
            0b0 => Self::Telemetry,
            0b1 => Self::Telecommand,
            _ => unreachable!()
        }
    }

    /// returns boolean indicating if instance of [PacketType] is [PacketType::Telecommand]
    pub fn is_telecommand(&self) -> bool {
        matches!(self, Self::Telecommand)
    }

    /// returns boolean indicating if instance of [PacketType] is [PacketType::Telemetry]
    pub fn is_telemetry(&self) -> bool {
        matches!(self, Self::Telemetry)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Sequence flag indicating if the packet is the start, end, or continuation in a sequence of
/// packets, or is the packet is unsegmented.
pub enum SequenceFlag {
    Continuation = 0,
    Start = 1,
    End = 2,
    Unsegmented = 3,
}

impl SequenceFlag {
    /// Converts the [SequenceFlag] enum into its bitwise representation to be used in the SPP
    /// primary header.
    pub fn to_bits(&self) -> u16 {
        match self {
            Self::Continuation => 0b00,
            Self::Start => 0b01,
            Self::End => 0b10,
            Self::Unsegmented => 0b11,
        }
    }

    /// Converts the raw bits (after being shifted) from the sequence control portion of the primary
    /// header into [SequenceFlag].
    pub fn from_bits(bits: u16) -> Self {
        match bits & 0b11 {
            0b00 => Self::Continuation,
            0b01 => Self::Start,
            0b10 => Self::End,
            0b11 => Self::Unsegmented,
            _ => unreachable!()
        }
    }

    /// returns boolean indicating if instance of [SequenceFlag] is [SequenceFlag::Continuation]
    pub fn is_continuation(&self) -> bool {
        matches!(self, Self::Continuation)
    }

    /// returns boolean indicating if instance of [SequenceFlag] is [SequenceFlag::Start]
    pub fn is_start(&self) -> bool {
        matches!(self, Self::Start)
    }

    /// returns boolean indicating if instance of [SequenceFlag] is [SequenceFlag::End]
    pub fn is_end(&self) -> bool {
        matches!(self, Self::End)
    }
    /// returns boolean indicating if instance of [SequenceFlag] is [SequenceFlag::Unsegmented]
    pub fn is_unsegmented(&self) -> bool {
        matches!(self, Self::Unsegmented)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Primary Header used in the Space Packet Protocol.
///
/// This data structure encapsulates the packet version number, packet identification, 
/// and sequence control field of the primary header of a SPP Packet. It is possible, although
/// not neccessary to work with the PrimaryHeader Struct directly. 
///
/// Typical usage involves creating a SpacePacket, which internally constructs the PrimaryHeader
/// using the arguments passed.
/// ``` rust
/// use ccsds::spp::{SpacePacket, PacketType, SequenceFlag};
/// # fn main () {
/// // generates new SpacePacket, internally constructing the PrimaryHeader.
/// let my_space_packet = SpacePacket::new(
///     PacketType::Telecommand,
///     false,
///     17,
///     SequenceFlag::Unsegmented,
///     0,
///     "Cool Space Data".as_bytes().to_vec()
/// );
/// # }
/// ```
///
/// Note that the user data length field is not included as a field within PrimaryHeader,
/// The data length field is generated at encoding time of the SpacePacket.
pub struct PrimaryHeader {

    /// Hardcoded to 0b000, but here incase standard changes in the future (3 bits)
    pub version: u8,

    /// Packet type defined by [PacketType] enum (1 bit)
    pub packet_type: PacketType,

    /// Indicates if secondary header is used (1 bit)
    pub secondary_header: bool,

    /// Application process ID of the packet (11 bits)
    pub apid: u16,

    /// Sequence flag defined by [SequenceFlag] (2 bits)
    pub sequence_flag: SequenceFlag,

    /// Sequence number (14 bits)
    pub sequence_number: u16,
}

impl PrimaryHeader {
    /// Hardcoded version number for SPP
    const VERSION: u8 = 0b000;

    /// Number of bits the [VERSION] needs to be shifted in the
    /// [encode] function.
    const VERSION_SHIFT: usize = 13;
    /// Number of bits the [PacketType] bit needs to be shifted in the
    /// [encode] function.
    const PACKET_TYPE_SHIFT: usize = 12;
    /// Number of bits the secondary_header bit needs to be shifted in the
    /// [encode] function.
    const SECONDARY_HEADER_SHIFT: usize = 11;
    /// Number of bits the apid needs to be shifted in the
    /// [encode] function.
    const APID_SHIFT: usize = 0;
    /// Number of bits the [SequenceFlag] bits needs to be shifted in the
    /// [encode] function.
    const SEQUENCE_FLAG_SHIFT: usize = 14;

    /// Mask of [PacketType] bit in the decode function.
    const PACKET_TYPE_MASK: u16 = 0x1000;
    /// Mask of secondary_header bit in the decode function.
    const SECONDARY_HEADER_MASK: u16 = 0x0800;
    /// Mask of apid bits in the decode function.
    const APID_MASK: u16 = 0x03FF;
    /// Mask of [SequenceFlag] bits in the decode function.
    const SEQUENCE_FLAG_MASK: u16 = 0xC000;
    /// Mask of sequence_number bits in the decode function.
    const SEQUENCE_NUMBER_MASK: u16 = 0x3FFF;

    /// Encodes the primary header into a vector of big endian bytes as described by CCSDS 133.0-B-2.
    pub fn encode(&self) -> Vec<u8> {
        let packet_id =
            u16::from(Self::VERSION) << Self::VERSION_SHIFT |
            self.packet_type.to_bits() << Self::PACKET_TYPE_SHIFT |
            u16::from(self.secondary_header) << Self::SECONDARY_HEADER_SHIFT |
            self.apid & Self::APID_MASK << Self::APID_SHIFT;

        let sequence_ctl =
            self.sequence_flag.to_bits() << Self::SEQUENCE_FLAG_SHIFT |
            self.sequence_number & Self::SEQUENCE_NUMBER_MASK;

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&u16::to_be_bytes(packet_id));
        encoded.extend_from_slice(&u16::to_be_bytes(sequence_ctl));

        encoded
    }
    
    /// Decodes the primary header from a source that implements [Read]. Returns the result of the
    /// operation, on success giving the decoded [PrimaryHeader].
    pub fn decode<R: Read>(buf: &mut R) -> std::io::Result<Self> {
        let mut tmp = [0u8; 4];
        buf.read_exact(&mut tmp)?;

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
    fn test_spp_primary_header_codec(
        #[values(PacketType::Telecommand, PacketType::Telemetry)]
        packet_type: PacketType,
        #[values(true, false)]
        secondary_header: bool,
        #[values(SequenceFlag::Continuation, SequenceFlag::Start, SequenceFlag::End, SequenceFlag::Unsegmented)]
        sequence_flag: SequenceFlag,
    ) {
        let expected = PrimaryHeader {
            version: PrimaryHeader::VERSION,
            packet_type,
            secondary_header,
            apid: 0,
            sequence_flag,
            sequence_number: 0
        };
        let encoded = expected.encode();
        let found = PrimaryHeader::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(expected, found)
    }

    #[rstest]
    #[case("Hello, World!".as_bytes().to_vec())]
    #[case(vec![0])]
    #[case(vec![0u8; u16::MAX as usize])]
    fn test_test_spp_packet_codec(
        #[values(PacketType::Telecommand, PacketType::Telemetry)]
        packet_type: PacketType,
        #[values(true, false)]
        secondary_header: bool,
        #[values(SequenceFlag::Continuation, SequenceFlag::Start, SequenceFlag::End, SequenceFlag::Unsegmented)]
        sequence_flag: SequenceFlag,
        #[case] payload: Vec<u8>,
    ) {
        let expected = SpacePacket::new(packet_type, secondary_header, 0, sequence_flag, 0, payload);
        let encoded = expected.encode();
        let found = SpacePacket::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(expected.primary_header, found.primary_header);
        assert_eq!(expected.payload, found.payload)
    }
}



