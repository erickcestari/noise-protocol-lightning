use bitcoin_hashes::{
    Hkdf,
    hex::{Case, DisplayHex},
    sha256,
};
use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};
use secp256k1::{Keypair, PublicKey};

use crate::{PROLOGUE, PROTOCOL_NAME};

const INFO: [u8; 0] = [];
pub struct Noise {
    pub responder_pubkey: PublicKey,
    pub initiator_keys: Keypair,
    pub hash: sha256::Hash,
    pub ck: [u8; 32],
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
        }
    }

    pub fn act_one(&mut self) {
        let secp = secp256k1::Secp256k1::new();
        // let secret_key = rand::rng().random::<[u8; 32]>();
        // let ephemeral_keypair = Keypair::from_seckey_byte_array(&secp, secret_key).unwrap();
        // Predefined ephemeral keys
        let ls_priv_hex = "1212121212121212121212121212121212121212121212121212121212121212";
        let ls_priv_bytes = hex::decode(ls_priv_hex).unwrap();
        let mut ls_priv_array = [0u8; 32];
        ls_priv_array.copy_from_slice(&ls_priv_bytes);
        let ephemeral_keypair = Keypair::from_seckey_byte_array(&secp, ls_priv_array).unwrap();
        // h = SHA256(h || ephemeral_pubkey)
        self.hash = sha256::Hash::hash(&concat_bytes(&[
            self.hash.as_byte_array(),
            &ephemeral_keypair.public_key().serialize(),
        ]));

        println!("h: {}", self.hash.to_string());

        println!(
            "&self.responder_pubkey: {}",
            &self.responder_pubkey.to_string()
        );
        println!(
            "&ephemeral_keypair.secret key(): {}",
            &ephemeral_keypair.secret_bytes().to_hex_string(Case::Lower)
        );

        let es_shared_secret = secp256k1::ecdh::SharedSecret::new(
            &self.responder_pubkey,
            &ephemeral_keypair.secret_key(),
        );

        println!(
            "full shared point: {}",
            es_shared_secret.secret_bytes().to_hex_string(Case::Lower)
        );
        let hkdf = Hkdf::<sha256::Hash>::new(&self.ck, &es_shared_secret.secret_bytes());
        let mut okm = [0u8; 64];
        hkdf.expand(&INFO, &mut okm).unwrap();
        self.ck = okm[..32].try_into().unwrap();
        let temp_k1: [u8; 32] = okm[32..].try_into().unwrap();

        println!("ck: {}", self.ck.to_hex_string(Case::Lower));
        println!("temp_k1: {}", temp_k1.to_hex_string(Case::Lower));
        let mut hash_bytes: Vec<u8> = self.hash.clone().to_byte_array().to_vec();
        let message_tag = encrypt_with_ad(temp_k1, 0, &mut hash_bytes, &mut []);
        println!("message_tag: {}", message_tag.to_hex_string(Case::Lower));
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

fn concat_bytes<'a>(slices: &[&'a [u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut buf = Vec::with_capacity(total_len);
    for slice in slices {
        buf.extend_from_slice(slice);
    }
    buf
}
