pub trait Message {
    fn get_type(&self) -> u16;
    fn encode(&self) -> Vec<u8>;
    fn decode(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Init = 16,
    Error = 17,
    Warning = 18,
    OpenChannel = 32,
    AcceptChannel = 33,
    FundingCreated = 34,
    FundingSigned = 35,
    ChannelReady = 36,
    Shutdown = 38,
    ClosingSigned = 39,
    UpdateAddHtlc = 128,
    UpdateFulfillHtlc = 130,
    UpdateFailHtlc = 131,
    CommitmentSigned = 132,
    RevokeAndAck = 133,
    UpdateFee = 134,
    UpdateFailMalformedHtlc = 135,
    ChannelReestablish = 136,
    ChannelAnnouncement = 256,
    NodeAnnouncement = 257,
    ChannelUpdate = 258,
    AnnounceSignatures = 259,
    QueryShortChannelIds = 261,
    ReplyShortChannelIdsEnd = 262,
    QueryChannelRange = 263,
    ReplyChannelRange = 264,
    GossipTimestampFilter = 265,
    Unknown = 0,
}

impl MessageType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            16 => MessageType::Init,
            17 => MessageType::Error,
            18 => MessageType::Warning,
            32 => MessageType::OpenChannel,
            33 => MessageType::AcceptChannel,
            34 => MessageType::FundingCreated,
            35 => MessageType::FundingSigned,
            36 => MessageType::ChannelReady,
            38 => MessageType::Shutdown,
            39 => MessageType::ClosingSigned,
            128 => MessageType::UpdateAddHtlc,
            130 => MessageType::UpdateFulfillHtlc,
            131 => MessageType::UpdateFailHtlc,
            132 => MessageType::CommitmentSigned,
            133 => MessageType::RevokeAndAck,
            134 => MessageType::UpdateFee,
            135 => MessageType::UpdateFailMalformedHtlc,
            136 => MessageType::ChannelReestablish,
            256 => MessageType::ChannelAnnouncement,
            257 => MessageType::NodeAnnouncement,
            258 => MessageType::ChannelUpdate,
            259 => MessageType::AnnounceSignatures,
            261 => MessageType::QueryShortChannelIds,
            262 => MessageType::ReplyShortChannelIdsEnd,
            263 => MessageType::QueryChannelRange,
            264 => MessageType::ReplyChannelRange,
            265 => MessageType::GossipTimestampFilter,
            _ => MessageType::Unknown,
        }
    }

    pub fn to_u16(&self) -> u16 {
        *self as u16
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_u16(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.to_u16().to_be_bytes()
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Init => write!(f, "init"),
            MessageType::Error => write!(f, "error"),
            MessageType::Warning => write!(f, "warning"),
            MessageType::OpenChannel => write!(f, "open_channel"),
            MessageType::AcceptChannel => write!(f, "accept_channel"),
            MessageType::FundingCreated => write!(f, "funding_created"),
            MessageType::FundingSigned => write!(f, "funding_signed"),
            MessageType::ChannelReady => write!(f, "channel_ready"),
            MessageType::Shutdown => write!(f, "shutdown"),
            MessageType::ClosingSigned => write!(f, "closing_signed"),
            MessageType::UpdateAddHtlc => write!(f, "update_add_htlc"),
            MessageType::UpdateFulfillHtlc => write!(f, "update_fulfill_htlc"),
            MessageType::UpdateFailHtlc => write!(f, "update_fail_htlc"),
            MessageType::CommitmentSigned => write!(f, "commitment_signed"),
            MessageType::RevokeAndAck => write!(f, "revoke_and_ack"),
            MessageType::UpdateFee => write!(f, "update_fee"),
            MessageType::UpdateFailMalformedHtlc => write!(f, "update_fail_malformed_htlc"),
            MessageType::ChannelReestablish => write!(f, "channel_reestablish"),
            MessageType::ChannelAnnouncement => write!(f, "channel_announcement"),
            MessageType::NodeAnnouncement => write!(f, "node_announcement"),
            MessageType::ChannelUpdate => write!(f, "channel_update"),
            MessageType::AnnounceSignatures => write!(f, "announce_signatures"),
            MessageType::QueryShortChannelIds => write!(f, "query_short_channel_ids"),
            MessageType::ReplyShortChannelIdsEnd => write!(f, "reply_short_channel_ids_end"),
            MessageType::QueryChannelRange => write!(f, "query_channel_range"),
            MessageType::ReplyChannelRange => write!(f, "reply_channel_range"),
            MessageType::GossipTimestampFilter => write!(f, "gossip_timestamp_filter"),
            MessageType::Unknown => write!(f, "unknown"),
        }
    }
}