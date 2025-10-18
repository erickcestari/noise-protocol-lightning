use noise_protocol_lightning::client::NoiseClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Lightning Network Noise Protocol Client");
    println!("==========================================\n");

    // Parse responder public key
    let rs_pub_hex = "0364913d18a19c671bb36dd04d6ad5be0fe8f2894314c36a9db3f03c2d414907e1";
    let rs_pub_bytes = hex::decode(rs_pub_hex)?;
    let responder_public_key = secp256k1::PublicKey::from_slice(&rs_pub_bytes)?;

    let node_address = "192.243.215.102:9735";

    let mut client = NoiseClient::new(node_address, responder_public_key)?;

    match client.perform_handshake() {
        Ok(()) => {
            client.listen_for_messages()?;
        }
        Err(e) => {
            eprintln!("Handshake failed: {}", e);
            return Err(e);
        }
    }

    println!("Disconnected from Lightning node");
    Ok(())
}
