use bitcoin_hashes::{Hkdf, sha256};
use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::Rng;
use secp256k1::{Keypair, PublicKey, constants::PUBLIC_KEY_SIZE};

use crate::{ACT_TWO_BUFFER_SIZE, MESSAGE_VERSION, MESSAGE_VERSION_SIZE, PROLOGUE, PROTOCOL_NAME};

const INFO: [u8; 0] = [];
pub struct Noise {
    pub responder_pubkey: PublicKey,
    pub initiator_keys: Keypair,
    pub hash: sha256::Hash,
    pub ck: [u8; 32],
    pub secp: secp256k1::Secp256k1<secp256k1::All>,
    pub ephemeral_keypair: Option<Keypair>,
    pub responder_ephemeral_pubkey: Option<PublicKey>,
    pub temp_k2: Option<[u8; 32]>,
    pub receive_nounce: u64,
    pub send_nonce: u64,
    pub send_chaining_key: Option<[u8; 32]>,
    pub receive_chaining_key: Option<[u8; 32]>,
    pub encrypt_key: Option<[u8; 32]>,
    pub decrypt_key: Option<[u8; 32]>,
}

impl Noise {
    pub fn new(responder_pubkey: PublicKey, initiator_keys: Keypair) -> Self {
        // h = SHA256(PROTOCOL_NAME)
        let mut hash = sha256::Hash::hash(PROTOCOL_NAME.as_bytes());
        let ck = *hash.clone().as_byte_array();
        // h = SHA256(h || prologue)
        hash = sha256::Hash::hash(&concat_bytes(&[hash.as_byte_array(), PROLOGUE.as_bytes()]));
        // h = SHA256(h || responder_pubkey)
        hash = sha256::Hash::hash(&concat_bytes(&[
            hash.as_byte_array(),
            &responder_pubkey.serialize(),
        ]));
        Self {
            responder_pubkey,
            initiator_keys,
            hash,
            ck,
            secp: secp256k1::Secp256k1::new(),
            ephemeral_keypair: None,
            responder_ephemeral_pubkey: None,
            temp_k2: None,
            receive_nounce: 0,
            send_nonce: 0,
            send_chaining_key: None,
            receive_chaining_key: None,
            encrypt_key: None,
            decrypt_key: None,
        }
    }

    pub fn act_one(&mut self) -> Result<Vec<u8>, NoiseError> {
        let secret_key = rand::rng().random::<[u8; 32]>();
        let ephemeral_keypair = Keypair::from_seckey_byte_array(&self.secp, secret_key)
            .map_err(|_| NoiseError::EphemeralKeyGenerationFailed)?;
        // h = SHA256(h || ephemeral_pubkey)
        self.hash = sha256::Hash::hash(&concat_bytes(&[
            self.hash.as_byte_array(),
            &ephemeral_keypair.public_key().serialize(),
        ]));
        self.ephemeral_keypair = Some(ephemeral_keypair);

        let es_shared_secret = secp256k1::ecdh::SharedSecret::new(
            &self.responder_pubkey,
            &ephemeral_keypair.secret_key(),
        );

        let hkdf = Hkdf::<sha256::Hash>::new(&self.ck, &es_shared_secret.secret_bytes());
        let mut okm = [0u8; 64];
        hkdf.expand(&INFO, &mut okm)
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        self.ck = okm[..32]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        let temp_k1: [u8; 32] = okm[32..]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        let mut hash_bytes: Vec<u8> = self.hash.clone().to_byte_array().to_vec();
        let message_tag = encrypt_with_ad(temp_k1, 0, &mut hash_bytes, &mut []);

        self.hash = sha256::Hash::hash(&concat_bytes(&[self.hash.as_byte_array(), &message_tag]));

        // MESSAGE_VERSION || ephemeral_pubkey || encrypted_message_tag
        let message = concat_bytes(&[
            &MESSAGE_VERSION.to_le_bytes(),
            ephemeral_keypair.public_key().serialize().as_ref(),
            &message_tag,
        ]);

        Ok(message)
    }

    pub fn act_two(
        &mut self,
        act_two_message: [u8; ACT_TWO_BUFFER_SIZE],
    ) -> Result<(), NoiseError> {
        let version = act_two_message[0];
        if version != MESSAGE_VERSION {
            return Err(NoiseError::InvalidMessageVersion);
        }
        let responder_ephemeral_pubkey =
            PublicKey::from_slice(&act_two_message[MESSAGE_VERSION_SIZE..PUBLIC_KEY_SIZE + 1])
                .map_err(|_| NoiseError::InvalidSharedPublicKeyActTwo)?;
        self.responder_ephemeral_pubkey = Some(responder_ephemeral_pubkey);
        let message_tag = &act_two_message[PUBLIC_KEY_SIZE + 1..];

        // h = SHA256(h || responder_ephemeral_pubkey)
        self.hash = sha256::Hash::hash(&concat_bytes(&[
            self.hash.as_byte_array(),
            &responder_ephemeral_pubkey.serialize(),
        ]));

        let ee_shared_secret = secp256k1::ecdh::SharedSecret::new(
            &responder_ephemeral_pubkey,
            &self.ephemeral_keypair.unwrap().secret_key(),
        );

        let hkdf = Hkdf::<sha256::Hash>::new(&self.ck, &ee_shared_secret.secret_bytes());
        let mut okm = [0u8; 64];
        hkdf.expand(&INFO, &mut okm)
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        self.ck = okm[..32]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        let temp_k2: [u8; 32] = okm[32..]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        self.temp_k2 = Some(temp_k2);

        let hash_bytes: Vec<u8> = self.hash.clone().to_byte_array().to_vec();
        decrypt_with_ad(temp_k2, 0, &hash_bytes, &mut message_tag.to_vec());

        // h = SHA256(h || message_tag)
        self.hash = sha256::Hash::hash(&concat_bytes(&[self.hash.as_byte_array(), &message_tag]));
        Ok(())
    }

    pub fn act_three(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut initiator_pubkey = self.initiator_keys.public_key().serialize();
        let encrypted_pubkey = encrypt_with_ad(
            self.temp_k2.unwrap(),
            1,
            self.hash.as_byte_array(),
            &mut initiator_pubkey,
        );

        // h = SHA256(h || encrypted_pubkey)
        self.hash = sha256::Hash::hash(&concat_bytes(&[
            self.hash.as_byte_array(),
            &encrypted_pubkey,
        ]));

        let se_shared_secret = secp256k1::ecdh::SharedSecret::new(
            &self.responder_ephemeral_pubkey.unwrap(),
            &self.initiator_keys.secret_key(),
        );

        let hkdf = Hkdf::<sha256::Hash>::new(&self.ck, &se_shared_secret.secret_bytes());
        let mut okm = [0u8; 64];
        hkdf.expand(&INFO, &mut okm)
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        self.ck = okm[..32]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        let temp_3: [u8; 32] = okm[32..]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        self.receive_chaining_key = Some(self.ck);
        self.send_chaining_key = Some(self.ck);

        let mut hash_bytes: Vec<u8> = self.hash.clone().to_byte_array().to_vec();
        let message_tag = encrypt_with_ad(temp_3, 0, &mut hash_bytes, &mut []);

        let hkdf = Hkdf::<sha256::Hash>::new(&self.ck, &[]);
        let mut okm = [0u8; 64];
        hkdf.expand(&INFO, &mut okm)
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        let encrypt_key: [u8; 32] = okm[..32]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        let decrypt_key: [u8; 32] = okm[32..]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        self.encrypt_key = Some(encrypt_key);
        self.decrypt_key = Some(decrypt_key);

        // MESSAGE_VERSION || encrypted_initator_pubkey || message_tag
        let message = concat_bytes(&[
            &MESSAGE_VERSION.to_le_bytes(),
            &encrypted_pubkey,
            &message_tag,
        ]);

        Ok(message)
    }
}

fn encrypt_with_ad(
    key: [u8; 32],
    nonce: u64,
    associated_data: &[u8],
    plaintext: &mut [u8],
) -> Vec<u8> {
    // Encode nonce as: 32 zero bits + little-endian 64-bit value
    // This creates a 12-byte nonce (96 bits) as required by ChaCha20-Poly1305
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&nonce.to_le_bytes());

    // Create ChaCha20-Poly1305 cipher
    let nonce_ref = Nonce::new(nonce_bytes);
    let key_ref = Key::new(key);
    let cipher = ChaCha20Poly1305::new(key_ref, nonce_ref);

    // Encrypt the plaintext in place and get the authentication tag
    let tag = cipher.encrypt(plaintext, Some(associated_data));

    // Return ciphertext + tag
    let mut result = Vec::with_capacity(plaintext.len() + 16);
    result.extend_from_slice(plaintext); // Now contains ciphertext
    result.extend_from_slice(&tag); // Append 16-byte tag

    result
}

fn decrypt_with_ad(
    key: [u8; 32],
    nonce: u64,
    associated_data: &[u8],
    ciphertext: &mut [u8],
) -> Vec<u8> {
    // Encode nonce as: 32 zero bits + little-endian 64-bit value
    // This creates a 12-byte nonce (96 bits) as required by ChaCha20-Poly1305
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&nonce.to_le_bytes());

    // Create ChaCha20-Poly1305 cipher
    let nonce_ref = Nonce::new(nonce_bytes);
    let key_ref = Key::new(key);
    let cipher = ChaCha20Poly1305::new(key_ref, nonce_ref);

    let tag = ciphertext[ciphertext.len() - 16..ciphertext.len()]
        .try_into()
        .unwrap();
    let mut ciphertext = ciphertext[..ciphertext.len() - 16].to_vec();

    cipher
        .decrypt(&mut ciphertext, tag, Some(associated_data))
        .unwrap();

    ciphertext
}

fn concat_bytes<'a>(slices: &[&'a [u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut buf = Vec::with_capacity(total_len);
    for slice in slices {
        buf.extend_from_slice(slice);
    }
    buf
}
#[derive(Debug)]
pub enum NoiseError {
    InvalidMessageVersion,
    HkdfExpansionFailed,
    EphemeralKeyGenerationFailed,
    InvalidSharedPublicKeyActTwo,
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoiseError::InvalidMessageVersion => write!(f, "Invalid message version"),
            NoiseError::HkdfExpansionFailed => write!(f, "HKDF expansion failed"),
            NoiseError::EphemeralKeyGenerationFailed => {
                write!(f, "Ephemeral key generation failed")
            }
            NoiseError::InvalidSharedPublicKeyActTwo => {
                write!(f, "Invalid shared public key in Act Two message")
            }
        }
    }
}

impl std::error::Error for NoiseError {}
