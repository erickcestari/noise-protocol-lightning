use crate::messages::message::Message;

// Lightning Network Ping Message (type 18)
// Format:
// * [`u16`:`num_pong_bytes`] - number of bytes to be sent back in pong
// * [`u16`:`byteslen`] - length of ignored data
// * [`byteslen*byte`:`ignored`] - ignored data (SHOULD be 0s)
#[derive(Debug, Clone, PartialEq)]
pub struct Ping {
    pub num_pong_bytes: u16,
    pub ignored: Vec<u8>,
}

impl Ping {
    /// Creates a new Ping message
    /// 
    /// # Arguments
    /// * `num_pong_bytes` - Number of bytes to request in pong response (must be < 65532)
    /// * `ignored_len` - Length of ignored padding data (will be filled with zeros)
    pub fn new(num_pong_bytes: u16, ignored_len: u16) -> Self {
        Self {
            num_pong_bytes,
            ignored: vec![0u8; ignored_len as usize], // SHOULD set ignored to 0s per BOLT
        }
    }

    /// Creates a new Ping message with custom ignored data
    /// Warning: ignored data MUST NOT contain sensitive information per BOLT spec
    pub fn new_with_ignored(num_pong_bytes: u16, ignored: Vec<u8>) -> Self {
        Self {
            num_pong_bytes,
            ignored,
        }
    }

    /// Validates the ping message according to BOLT requirements
    pub fn is_valid(&self) -> bool {
        // Per BOLT: if num_pong_bytes >= 65532, the ping should be ignored
        self.num_pong_bytes < 65532
    }
}

impl Message for Ping {
    fn get_type(&self) -> u16 {
        18
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(4 + self.ignored.len());
        
        // Encode num_pong_bytes
        encoded.extend_from_slice(&self.num_pong_bytes.to_be_bytes());
        
        // Encode length of ignored data
        encoded.extend_from_slice(&(self.ignored.len() as u16).to_be_bytes());
        
        // Encode ignored data
        encoded.extend_from_slice(&self.ignored);
        
        encoded
    }

    fn decode(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if data.len() < 4 {
            return Err("Ping message too short".into());
        }
        
        let num_pong_bytes = u16::from_be_bytes([data[0], data[1]]);
        let byteslen = u16::from_be_bytes([data[2], data[3]]) as usize;
        
        if data.len() < 4 + byteslen {
            return Err("Ping message shorter than expected".into());
        }
        
        let ignored = data[4..4 + byteslen].to_vec();
        
        Ok(Self {
            num_pong_bytes,
            ignored,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_encode_decode() {
        let original = Ping::new_with_ignored(100, vec![0xde, 0xad, 0xbe, 0xef]);
        let encoded = original.encode();
        let decoded = Ping::decode(&encoded).unwrap();

        assert_eq!(decoded.num_pong_bytes, 100);
        assert_eq!(decoded.ignored, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_ping_empty_ignored() {
        let original = Ping::new(0, 0);
        let encoded = original.encode();
        let decoded = Ping::decode(&encoded).unwrap();

        assert_eq!(decoded.num_pong_bytes, 0);
        assert_eq!(decoded.ignored, vec![]);
    }
}
