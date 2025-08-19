use crate::messages::{message::Message, ping::Ping};

// Lightning Network Pong Message (type 19)
// Format:
// * [`u16`:`byteslen`] - length of ignored data
// * [`byteslen*byte`:`ignored`] - ignored data (SHOULD be 0s)
#[derive(Debug, Clone, PartialEq)]
pub struct Pong {
    pub ignored: Vec<u8>,
}

impl Pong {
    /// Creates a new Pong message in response to a Ping
    pub fn new(num_bytes: u16) -> Self {
        Self {
            ignored: vec![0u8; num_bytes as usize], // SHOULD set ignored to 0s per BOLT
        }
    }

    /// Creates a new Pong message with custom ignored data
    pub fn new_with_ignored(ignored: Vec<u8>) -> Self {
        Self { ignored }
    }

    /// Creates a pong response to a ping message
    pub fn from_ping(ping: &Ping) -> Option<Self> {
        if !ping.is_valid() {
            // Per BOLT: MUST ignore ping if num_pong_bytes >= 65532
            return None;
        }

        Some(Self::new(ping.num_pong_bytes))
    }
}

impl Message for Pong {
    fn get_type(&self) -> u16 {
        19
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + self.ignored.len());

        // Encode length of ignored data
        encoded.extend_from_slice(&(self.ignored.len() as u16).to_be_bytes());

        // Encode ignored data
        encoded.extend_from_slice(&self.ignored);

        encoded
    }

    fn decode(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if data.len() < 2 {
            return Err("Pong message too short".into());
        }

        let byteslen = u16::from_be_bytes([data[0], data[1]]) as usize;

        if data.len() < 2 + byteslen {
            return Err("Pong message shorter than expected".into());
        }

        let ignored = data[2..2 + byteslen].to_vec();

        Ok(Self { ignored })
    }
}
