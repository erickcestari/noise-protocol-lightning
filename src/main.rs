use std::{
    io::{Read, Write, Result as IoResult},
    net::TcpStream,
    time::Duration,
};

use noise_protocol_lightning::{noise::Noise, ACT_TWO_BUFFER_SIZE};
use rand::Rng;
use secp256k1::Keypair;

fn main() -> IoResult<()> {
    let secp = secp256k1::Secp256k1::new();

    // Predefined responder keys
    let rs_pub_hex = "035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226";
    let rs_pub_bytes = hex::decode(rs_pub_hex).unwrap();
    let responder_public_key = secp256k1::PublicKey::from_slice(&rs_pub_bytes).unwrap();

    // Predefined initiator keys
    let secret_key = rand::rng().random::<[u8; 32]>();
    let initiator_keys = Keypair::from_seckey_byte_array(&secp, secret_key).unwrap();

    let mut noise = Noise::new(responder_public_key, initiator_keys);
    let act_one_message = noise.act_one();
    println!("act one message: {}", hex::encode(act_one_message.clone()));

    // Connect to Lightning node
    let node_address = "170.75.163.209:9735";
    println!("Connecting to Lightning node at {}...", node_address);

    match connect_and_handshake(node_address, act_one_message, &mut noise) {
        Ok(act_two_message) => {
            println!(
                "Successfully received Act Two message: {}",
                hex::encode(act_two_message)
            );
            println!("Noise handshake Act One -> Act Two completed!");
        }
        Err(e) => {
            eprintln!("Failed to complete handshake: {}", e);
        }
    }

    Ok(())
}

fn connect_and_handshake(
    address: &str,
    act_one_message: Vec<u8>,
    noise: &mut Noise,
) -> IoResult<Vec<u8>> {
    use std::io::ErrorKind;

    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_nodelay(true)?;

    println!("Connected to Lightning node at {}", address);

    println!(
        "Sending Act One message ({} bytes): {}",
        act_one_message.len(),
        hex::encode(&act_one_message)
    );

    stream.write_all(&act_one_message)?;
    stream.flush()?;
    println!("✓ Act One message sent");

    println!("Waiting for Act Two response...");
    let mut act_two_buffer = vec![0u8; ACT_TWO_BUFFER_SIZE];

    match stream.read_exact(&mut act_two_buffer) {
        Ok(()) => {
            println!(
                "✓ Received Act Two message ({} bytes)",
                act_two_buffer.len()
            );
            Ok(act_two_buffer)
        }
        Err(e) => match e.kind() {
            ErrorKind::TimedOut => {
                eprintln!("✗ Timeout waiting for Act Two response");
                Err(e)
            }
            ErrorKind::UnexpectedEof => {
                eprintln!("✗ Connection closed by peer before receiving Act Two");
                Err(e)
            }
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
                eprintln!("✗ Connection reset by peer");
                Err(e)
            }
            _ => {
                eprintln!("✗ Error reading Act Two: {}", e);
                Err(e)
            }
        },
    }
}
