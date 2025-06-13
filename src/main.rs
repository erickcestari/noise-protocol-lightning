use noise_protocol_lightning::noise::Noise;
use secp256k1::Keypair;

fn main() {
    let secp = secp256k1::Secp256k1::new();
    
    // Predefined responder keys
    let rs_pub_hex = "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7";
    let rs_pub_bytes = hex::decode(rs_pub_hex).unwrap();
    let responder_public_key = secp256k1::PublicKey::from_slice(&rs_pub_bytes).unwrap();
    
    // Predefined initiator keys
    let ls_priv_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let ls_priv_bytes = hex::decode(ls_priv_hex).unwrap();
    let mut ls_priv_array = [0u8; 32];
    ls_priv_array.copy_from_slice(&ls_priv_bytes);
    let initiator_keys = Keypair::from_seckey_byte_array(&secp, ls_priv_array).unwrap();
    
    let mut noise = Noise::new(responder_public_key, initiator_keys);
    let message = noise.act_one();
    println!("act one message: {}", hex::encode(message));
}
