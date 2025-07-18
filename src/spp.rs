//! Provides functionality to create, encode, and decode Space Packet Protocol
//! packets specified by the CCSDS 133.0-B-2 June 2020 Standard.
//!
//! General Usage:
//! ``` rust
//! use ccsds_rs::spp::{SpacePacket, PacketType, SequenceFlag};
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

use thiserror::Error;

#[derive(Debug, PartialEq, Clone)]
/// SPP Packet as defined by the CCSDS 133.0-B-2 Standard.
pub struct SpacePacket {
    /// [PrimaryHeader] of the Space Protocol Packet
    pub primary_header: PrimaryHeader,

    /// Payload of Space Packet Protocol
    pub payload: Vec<u8>
}

impl SpacePacket {
    /// size of the user data length field 
    const DATA_LENGTH_SIZE: usize = 2;

    /// Index of user data
    const DATA_IDX: usize = 6;

    pub fn new(
        packet_type: PacketType, 
        secondary_header: bool,
        apid: u16,
        sequence_flag: SequenceFlag,
        sequence_number: u16,
        payload: Vec<u8>
    ) -> Self {
        assert!(payload.len() <= u16::MAX as usize, "user data must be less than 65536");
        assert!(!payload.is_empty(), "user data cannot be left empty");
        assert!(apid <= PrimaryHeader::APID_MASK, "application process ID is invalid");
        assert!(sequence_number <= PrimaryHeader::SEQUENCE_NUMBER_MASK, "sequence number is invalid");

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
    ///
    /// Decoding can fail for the following reasons:
    /// - Incomplete data resulting in failure to parse primary header
    /// - Insufficient data resulting in failure to parse user data
    ///
    /// Both of these errors are recoverable, and can most likely be resolved by reading more bytes
    /// from the source, and attempting to decode again
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let primary_header = PrimaryHeader::decode(buf)?;

        let data_len_bytes = buf
            .get(PrimaryHeader::PRIMARY_HEADER_LEN..(PrimaryHeader::PRIMARY_HEADER_LEN + Self::DATA_LENGTH_SIZE))
            .ok_or(Error::IncompleteHeader)?;

        // Add single byte back to payload length that we subtracted during encoding
        let payload_len = u16::from_be_bytes([data_len_bytes[0], data_len_bytes[1]]) + 1;

        let payload = buf
            .get(Self::DATA_IDX..(Self::DATA_IDX + payload_len as usize))
            .ok_or(Error::InsufficientData { expected: payload_len as usize, found: buf[Self::DATA_IDX..].len() })?
            .to_vec();

        Ok( Self { primary_header, payload } )
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
///
/// use ccsds_rs::spp::{SpacePacket, PacketType, SequenceFlag};
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

    /// Size of the primary header
    const PRIMARY_HEADER_LEN: usize = 4;

    /// Hardcoded version number for SPP
    const VERSION: u8 = 0b000;

    /// Number of bits the VERSION needs to be shifted in the
    /// encode function.
    const VERSION_SHIFT: usize = 13;
    /// Number of bits the [PacketType] bit needs to be shifted in the
    /// encode function.
    const PACKET_TYPE_SHIFT: usize = 12;
    /// Number of bits the secondary_header bit needs to be shifted in the
    /// encode function.
    const SECONDARY_HEADER_SHIFT: usize = 11;
    /// Number of bits the apid needs to be shifted in the
    /// encode function.
    const APID_SHIFT: usize = 0;
    /// Number of bits the [SequenceFlag] bits needs to be shifted in the
    /// encode function.
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

    /// Encodes the [PrimaryHeader] into a vector of big endian bytes as described by CCSDS 133.0-B-2.
    pub fn encode(&self) -> Vec<u8> {
        let packet_id =
            u16::from(self.version) << Self::VERSION_SHIFT |
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

    /// Decodes the [PrimaryHeader] from a source that implements [Read]. Returns the result of the
    /// operation, on success giving the decoded [PrimaryHeader].
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let bytes = buf.get(0..Self::PRIMARY_HEADER_LEN).ok_or(Error::IncompleteHeader)?;

        let packet_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let sequence_ctl = u16::from_be_bytes([bytes[2], bytes[3]]);

        let (version, packet_type, secondary_header, apid) = (
            (packet_id >> Self::VERSION_SHIFT) as u8,
            PacketType::from_bits((packet_id & Self::PACKET_TYPE_MASK) >> Self::PACKET_TYPE_SHIFT),
            packet_id & Self::SECONDARY_HEADER_MASK != 0,
            packet_id & Self::APID_MASK,
        );

        if version != Self::VERSION {
            return Err(Error::Unsupported(version))
        }

        let (sequence_flag, sequence_number) = (
            SequenceFlag::from_bits((sequence_ctl & Self::SEQUENCE_FLAG_MASK) >> Self::SEQUENCE_FLAG_SHIFT),
            sequence_ctl & Self::SEQUENCE_NUMBER_MASK
        );

        Ok(Self {version, packet_type, secondary_header, apid, sequence_flag, sequence_number})
    }
}

#[derive(Debug, Error, PartialEq)]
/// Enum protraying various errors encountered during decoding of [PrimaryHeader] and
/// [SpacePacket].
pub enum Error {
    #[error("space packet protocol version {} not supported", .0)]    
    Unsupported(u8),

    /// Occurs when parsing the primary header fails
    #[error("incomplete primary header")]
    IncompleteHeader,

    /// Occurs when parsing user data payload fails
    #[error("insufficient data to complete decoding, found {}B but expected {}B", .found, .expected)]
    InsufficientData{ expected: usize, found: usize },
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
        let found = PrimaryHeader::decode(&encoded).unwrap();
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
        let found = SpacePacket::decode(&encoded).unwrap();
        assert_eq!(expected.primary_header, found.primary_header);
        assert_eq!(expected.payload, found.payload)
    }

    #[rstest]
    #[should_panic]
    fn test_empty_user_data() {
        let expected = SpacePacket::new(PacketType::Telemetry, false, 0, SequenceFlag::Continuation, 0, vec![]);
        let encoded = expected.encode();
        let found = SpacePacket::decode(&encoded).unwrap();
        assert_eq!(expected.primary_header, found.primary_header);
        assert_eq!(expected.payload, found.payload)
    }

    #[rstest]
    fn test_incomplete_header_err(
        #[values(1, 2, 3, 4, 5)] header_len: usize
    ) {
        let forged_header_packet = vec![0u8; header_len];
        assert_eq!(SpacePacket::decode(&forged_header_packet), Err(Error::IncompleteHeader))
    }

    #[rstest]
    #[case(vec![1; 5])]
    #[case(vec![1; 1])]
    #[case(vec![1; 128])]
    #[case(vec![1; 12048])]
    #[case(vec![1; 60000])]
    fn test_insufficient_data_err(#[case] payload: Vec<u8>) {
        let mut packet = PrimaryHeader {
            version: PrimaryHeader::VERSION,
            packet_type: PacketType::Telecommand,
            secondary_header: false,
            apid: 0,
            sequence_flag: SequenceFlag::End,
            sequence_number: 0
        }.encode();

        let bad_payload_len = payload.len() as u16 + 5 - 1;
        packet.extend_from_slice(&u16::to_be_bytes(bad_payload_len));
        packet.extend_from_slice(&payload);

        assert_eq!(SpacePacket::decode(&packet), Err(Error::InsufficientData { expected: (bad_payload_len + 1) as usize, found: payload.len()  }))
    }


    #[rstest]
    fn test_unsupported_err(#[values(1, 2, 3, 4, 5, 6, 7)] version: u8) {
        let mut packet = SpacePacket::new(
            PacketType::Telemetry,
            false,
            0,
            SequenceFlag::Continuation,
            0,
            vec![1]
        );

        packet.primary_header.version = version;

        let encoded = packet.encode();

        assert_eq!(SpacePacket::decode(&encoded), Err(Error::Unsupported(version)))
    }
}
