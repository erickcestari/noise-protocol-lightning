use bitcoin_hashes::{Hkdf, sha256};
use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::Rng;
use secp256k1::{Keypair, PublicKey, constants::PUBLIC_KEY_SIZE};

use crate::{ACT_TWO_BUFFER_SIZE, MESSAGE_VERSION, MESSAGE_VERSION_SIZE, PROLOGUE, PROTOCOL_NAME};

const INFO: [u8; 0] = [];
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const LENGTH_PREFIX_SIZE: usize = 18;
const ENCRYPTED_LENGTH_SIZE: usize = 2;

pub struct Noise {
    pub responder_pubkey: PublicKey,
    pub initiator_keys: Keypair,
    pub hash: sha256::Hash,
    pub ck: [u8; 32],
    pub secp: secp256k1::Secp256k1<secp256k1::All>,
    pub ephemeral_keypair: Option<Keypair>,
    pub responder_ephemeral_pubkey: Option<PublicKey>,
    pub temp_k2: Option<[u8; 32]>,
    pub receive_nonce: u64,
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
        let ck = *hash.as_byte_array();

        // h = SHA256(h || prologue)
        hash = Self::update_hash(&hash, PROLOGUE.as_bytes());

        // h = SHA256(h || responder_pubkey)
        hash = Self::update_hash(&hash, &responder_pubkey.serialize());

        Self {
            responder_pubkey,
            initiator_keys,
            hash,
            ck,
            secp: secp256k1::Secp256k1::new(),
            ephemeral_keypair: None,
            responder_ephemeral_pubkey: None,
            temp_k2: None,
            receive_nonce: 0,
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
        self.hash = Self::update_hash(&self.hash, &ephemeral_keypair.public_key().serialize());
        self.ephemeral_keypair = Some(ephemeral_keypair);

        let es_shared_secret = secp256k1::ecdh::SharedSecret::new(
            &self.responder_pubkey,
            &ephemeral_keypair.secret_key(),
        );

        let (new_ck, temp_k1) = self.derive_keys(&es_shared_secret.secret_bytes())?;
        self.ck = new_ck;

        let hash_bytes = self.hash.to_byte_array().to_vec();
        let message_tag = encrypt_with_ad(temp_k1, 0, &hash_bytes, &mut []);

        self.hash = Self::update_hash(&self.hash, &message_tag);

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
        self.hash = Self::update_hash(&self.hash, &responder_ephemeral_pubkey.serialize());

        let ee_shared_secret = secp256k1::ecdh::SharedSecret::new(
            &responder_ephemeral_pubkey,
            &self.ephemeral_keypair.unwrap().secret_key(),
        );

        let (new_ck, temp_k2) = self.derive_keys(&ee_shared_secret.secret_bytes())?;
        self.ck = new_ck;
        self.temp_k2 = Some(temp_k2);

        let hash_bytes = self.hash.to_byte_array().to_vec();
        let _ = decrypt_with_ad(temp_k2, 0, &hash_bytes, &mut message_tag.to_vec());

        // h = SHA256(h || message_tag)
        self.hash = Self::update_hash(&self.hash, message_tag);
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
        self.hash = Self::update_hash(&self.hash, &encrypted_pubkey);

        let se_shared_secret = secp256k1::ecdh::SharedSecret::new(
            &self.responder_ephemeral_pubkey.unwrap(),
            &self.initiator_keys.secret_key(),
        );

        let (new_ck, temp_k3) = self.derive_keys(&se_shared_secret.secret_bytes())?;
        self.ck = new_ck;

        self.receive_chaining_key = Some(self.ck);
        self.send_chaining_key = Some(self.ck);

        let hash_bytes = self.hash.to_byte_array().to_vec();
        let message_tag = encrypt_with_ad(temp_k3, 0, &hash_bytes, &mut []);

        // Derive final encryption/decryption keys
        self.derive_final_keys()?;

        // MESSAGE_VERSION || encrypted_initiator_pubkey || message_tag
        let message = concat_bytes(&[
            &MESSAGE_VERSION.to_le_bytes(),
            &encrypted_pubkey,
            &message_tag,
        ]);

        Ok(message)
    }

    /// Decrypts the 18-byte encrypted length prefix to get the message length
    pub fn decrypt_length(&mut self, encrypted_length: &[u8]) -> Result<u16, NoiseError> {
        if encrypted_length.len() != LENGTH_PREFIX_SIZE {
            return Err(NoiseError::InvalidLengthPrefix);
        }

        let decrypt_key = self.decrypt_key.ok_or(NoiseError::DecryptKeyNotSet)?;
        let ciphertext = self.decrypt_data(encrypted_length, decrypt_key, self.receive_nonce)?;

        if ciphertext.len() != ENCRYPTED_LENGTH_SIZE {
            return Err(NoiseError::InvalidLengthPrefix);
        }

        let length = u16::from_be_bytes([ciphertext[0], ciphertext[1]]);
        Ok(length)
    }

    /// Decrypts a message payload using the current receive key and nonce
    pub fn decrypt_message(&mut self, encrypted_message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if encrypted_message.len() < TAG_SIZE {
            return Err(NoiseError::MessageTooShort);
        }

        let decrypt_key = self.decrypt_key.ok_or(NoiseError::DecryptKeyNotSet)?;
        let ciphertext = self.decrypt_data(encrypted_message, decrypt_key, self.receive_nonce)?;

        self.receive_nonce += 1;
        Ok(ciphertext)
    }

    pub fn encrypt_and_format_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if message.len() > 65535 {
            return Err(NoiseError::MessageTooLong);
        }

        // Step 1: Encrypt the length prefix (2 bytes big-endian)
        let length = message.len() as u16;
        let encrypted_length = self.encrypt_length(length)?;

        // Step 2: Encrypt the message payload
        let encrypted_message = self.encrypt_message(message)?;

        // Step 3: Concatenate encrypted length prefix and encrypted message
        let mut output = Vec::with_capacity(encrypted_length.len() + encrypted_message.len());
        output.extend_from_slice(&encrypted_length);
        output.extend_from_slice(&encrypted_message);

        Ok(output)
    }

    /// Encrypts a message payload using the current send key and nonce
    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let encrypt_key = self.encrypt_key.ok_or(NoiseError::EncryptKeyNotSet)?;
        let encrypted_data = self.encrypt_data(message, encrypt_key, self.send_nonce)?;

        self.send_nonce += 1;
        Ok(encrypted_data)
    }

    /// Encrypts the 2-byte message length into an 18-byte encrypted length prefix
    pub fn encrypt_length(&mut self, length: u16) -> Result<Vec<u8>, NoiseError> {
        let length_bytes = length.to_be_bytes();
        let encrypt_key = self.encrypt_key.ok_or(NoiseError::EncryptKeyNotSet)?;
        let encrypted_length = self.encrypt_data(&length_bytes, encrypt_key, self.send_nonce)?;

        self.send_nonce += 1;
        Ok(encrypted_length)
    }

    fn encrypt_data(
        &self,
        plaintext: &[u8],
        key: [u8; 32],
        nonce: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        let mut plaintext_copy = plaintext.to_vec();
        let nonce_bytes = Self::create_nonce(nonce);
        let cipher = ChaCha20Poly1305::new(Key::new(key), Nonce::new(nonce_bytes));

        let tag = cipher.encrypt(&mut plaintext_copy, None);

        let mut result = Vec::with_capacity(plaintext.len() + TAG_SIZE);
        result.extend_from_slice(&plaintext_copy);
        result.extend_from_slice(&tag);
        Ok(result)
    }

    fn update_hash(current_hash: &sha256::Hash, data: &[u8]) -> sha256::Hash {
        sha256::Hash::hash(&concat_bytes(&[current_hash.as_byte_array(), data]))
    }

    fn derive_keys(&self, shared_secret: &[u8]) -> Result<([u8; 32], [u8; 32]), NoiseError> {
        let hkdf = Hkdf::<sha256::Hash>::new(&self.ck, shared_secret);
        let mut okm = [0u8; 64];
        hkdf.expand(&INFO, &mut okm)
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        let ck = okm[..32]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        let temp_key = okm[32..]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        Ok((ck, temp_key))
    }

    fn derive_final_keys(&mut self) -> Result<(), NoiseError> {
        let hkdf = Hkdf::<sha256::Hash>::new(&self.ck, &[]);
        let mut okm = [0u8; 64];
        hkdf.expand(&INFO, &mut okm)
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        let encrypt_key = okm[..32]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;
        let decrypt_key = okm[32..]
            .try_into()
            .map_err(|_| NoiseError::HkdfExpansionFailed)?;

        self.encrypt_key = Some(encrypt_key);
        self.decrypt_key = Some(decrypt_key);
        Ok(())
    }

    fn decrypt_data(
        &self,
        encrypted_data: &[u8],
        key: [u8; 32],
        nonce: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        let ciphertext_len = encrypted_data.len() - TAG_SIZE;
        let mut ciphertext = encrypted_data[..ciphertext_len].to_vec();
        let tag = &encrypted_data[ciphertext_len..];

        let nonce_bytes = Self::create_nonce(nonce);
        let cipher = ChaCha20Poly1305::new(Key::new(key), Nonce::new(nonce_bytes));

        let tag_array: [u8; TAG_SIZE] = tag.try_into().map_err(|_| NoiseError::InvalidTag)?;

        cipher
            .decrypt(&mut ciphertext, tag_array, None)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        Ok(ciphertext)
    }

    fn create_nonce(nonce: u64) -> [u8; NONCE_SIZE] {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[4..12].copy_from_slice(&nonce.to_le_bytes());
        nonce_bytes
    }
}

fn encrypt_with_ad(
    key: [u8; 32],
    nonce: u64,
    associated_data: &[u8],
    plaintext: &mut [u8],
) -> Vec<u8> {
    let nonce_bytes = Noise::create_nonce(nonce);
    let cipher = ChaCha20Poly1305::new(Key::new(key), Nonce::new(nonce_bytes));

    let tag = cipher.encrypt(plaintext, Some(associated_data));

    let mut result = Vec::with_capacity(plaintext.len() + TAG_SIZE);
    result.extend_from_slice(plaintext);
    result.extend_from_slice(&tag);
    result
}

fn decrypt_with_ad(
    key: [u8; 32],
    nonce: u64,
    associated_data: &[u8],
    ciphertext: &mut [u8],
) -> Vec<u8> {
    let nonce_bytes = Noise::create_nonce(nonce);
    let cipher = ChaCha20Poly1305::new(Key::new(key), Nonce::new(nonce_bytes));

    let tag = ciphertext[ciphertext.len() - TAG_SIZE..]
        .try_into()
        .unwrap();
    let mut ciphertext = ciphertext[..ciphertext.len() - TAG_SIZE].to_vec();

    cipher
        .decrypt(&mut ciphertext, tag, Some(associated_data))
        .unwrap();
    ciphertext
}

fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut buf = Vec::with_capacity(total_len);
    for slice in slices {
        buf.extend_from_slice(slice);
    }
    buf
}

#[derive(Debug)]
pub enum NoiseError {
    EncryptKeyNotSet,
    EncryptionFailed,
    InvalidMessageVersion,
    HkdfExpansionFailed,
    EphemeralKeyGenerationFailed,
    InvalidSharedPublicKeyActTwo,
    InvalidLengthPrefix,
    DecryptKeyNotSet,
    DecryptionFailed,
    InvalidTag,
    MessageTooLong,
    MessageTooShort,
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
            NoiseError::InvalidLengthPrefix => write!(f, "Invalid length prefix"),
            NoiseError::DecryptKeyNotSet => write!(f, "Decrypt key not set"),
            NoiseError::DecryptionFailed => write!(f, "Decryption failed"),
            NoiseError::InvalidTag => write!(f, "Invalid authentication tag"),
            NoiseError::MessageTooShort => write!(f, "Message too short to contain valid data"),
            NoiseError::EncryptKeyNotSet => write!(f, "Encrypt key not set"),
            NoiseError::EncryptionFailed => write!(f, "Encryption failed"),
            NoiseError::MessageTooLong => write!(f, "Message too long to be encrypted"),
        }
    }
}

impl std::error::Error for NoiseError {}
