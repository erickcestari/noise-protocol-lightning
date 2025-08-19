use noise_protocol_lightning::client::NoiseClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Lightning Network Noise Protocol Client");
    println!("==========================================\n");

    // Parse responder public key
    let rs_pub_hex = "03881f3ab4af423c7a78116ef01d31a65e694c468c23b11271d6caff94f5029f5a";
    let rs_pub_bytes = hex::decode(rs_pub_hex)?;
    let responder_public_key = secp256k1::PublicKey::from_slice(&rs_pub_bytes)?;

    let node_address = "192.168.2.12:9735";

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
