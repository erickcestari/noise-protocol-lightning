use noise_protocol_lightning::client::NoiseClient;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Lightning Network Noise Protocol Client");
    println!("==========================================\n");

    // Parse responder public key
    let rs_pub_hex = "035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226";
    let rs_pub_bytes = hex::decode(rs_pub_hex)?;
    let responder_public_key = secp256k1::PublicKey::from_slice(&rs_pub_bytes)?;

    let node_address = "170.75.163.209:9735";

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
