use std::{
    io::{Read, Result as IoResult, Write},
    net::TcpStream,
    time::Duration,
};

use rand::Rng;
use secp256k1::Keypair;

use crate::{ACT_TWO_BUFFER_SIZE, noise::Noise};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_BUFFER_SIZE: usize = 1024;

pub struct NoiseClient {
    pub stream: TcpStream,
    pub noise: Noise,
}

impl NoiseClient {
    pub fn new(
        address: &str,
        responder_public_key: secp256k1::PublicKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let secp = secp256k1::Secp256k1::new();

        let secret_key = rand::rng().random::<[u8; 32]>();
        let initiator_keys = Keypair::from_seckey_byte_array(&secp, secret_key)?;

        let noise = Noise::new(responder_public_key, initiator_keys);

        let stream = Self::connect_tcp(address)?;

        Ok(Self { stream, noise })
    }

    fn connect_tcp(address: &str) -> IoResult<TcpStream> {
        println!("Connecting to Lightning node at {}...", address);

        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        stream.set_nodelay(true)?;

        println!("✓ Connected to Lightning node at {}", address);
        Ok(stream)
    }

    pub fn perform_handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Act One
        let act_one_message = self.noise.act_one()?;
        self.send_message(&act_one_message, "Act One")?;

        // Act Two
        let act_two_message = self.receive_act_two()?;
        self.noise.act_two(act_two_message.try_into().unwrap())?;

        // Act Three
        let act_three_message = self.noise.act_three()?;
        self.send_message(&act_three_message, "Act Three")?;

        println!("Noise handshake completed successfully!");
        Ok(())
    }

    fn send_message(&mut self, message: &[u8], message_type: &str) -> IoResult<()> {
        println!(
            "Sending {} message ({} bytes): {}",
            message_type,
            message.len(),
            hex::encode(message)
        );

        self.stream.write_all(message)?;
        self.stream.flush()?;
        println!("✓ {} message sent", message_type);

        Ok(())
    }

    fn receive_act_two(&mut self) -> IoResult<Vec<u8>> {
        println!("Waiting for Act Two response...");
        let mut act_two_buffer = vec![0u8; ACT_TWO_BUFFER_SIZE];

        match self.stream.read_exact(&mut act_two_buffer) {
            Ok(()) => {
                println!(
                    "✓ Received Act Two message ({} bytes)",
                    act_two_buffer.len()
                );
                Ok(act_two_buffer)
            }
            Err(e) => {
                self.handle_read_error(&e, "Act Two");
                Err(e)
            }
        }
    }

    pub fn listen_for_messages(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\nStarting to listen for incoming messages...");
        println!("Press Ctrl+C to stop listening\n");

        let mut message_count = 0;
        let mut buffer = vec![0u8; MESSAGE_BUFFER_SIZE];

        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    println!("Connection closed by peer");
                    break;
                }
                Ok(bytes_read) => {
                    message_count += 1;
                    self.handle_received_message(&buffer[..bytes_read], message_count);
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        println!("No messages received (timeout)");
                        continue;
                    }
                    std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::UnexpectedEof => {
                        println!("Connection terminated: {}", e);
                        break;
                    }
                    _ => {
                        eprintln!("Error reading message: {}", e);
                        return Err(e.into());
                    }
                },
            }
        }

        println!("\nTotal messages received: {}", message_count);
        Ok(())
    }

    fn handle_received_message(&self, data: &[u8], message_number: usize) {
        println!("Message #{} ({} bytes):", message_number, data.len());
        println!("   Hex: {}", hex::encode(data));
    }

    fn handle_read_error(&self, error: &std::io::Error, context: &str) {
        match error.kind() {
            std::io::ErrorKind::TimedOut => {
                eprintln!("✗ Timeout waiting for {} response", context);
            }
            std::io::ErrorKind::UnexpectedEof => {
                eprintln!("✗ Connection closed by peer before receiving {}", context);
            }
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                eprintln!("✗ Connection reset by peer");
            }
            _ => {
                eprintln!("✗ Error reading {}: {}", context, error);
            }
        }
    }
}
