use std::{
    io::{BufWriter, IoSlice, Read, Result as IoResult, Write},
    net::TcpStream,
    os::fd::AsRawFd,
    time::Duration,
};

use rand::Rng;
use secp256k1::Keypair;

use crate::{ACT_TWO_BUFFER_SIZE, messages::message::MessageType, noise::Noise};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_BUFFER_SIZE: usize = 65536;

pub struct NoiseClient {
    pub stream: TcpStream,
    pub noise: Noise,
    message_buffer: Vec<u8>,
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

        Ok(Self {
            stream,
            noise,
            message_buffer: Vec::new(),
        })
    }

    fn connect_tcp(address: &str) -> IoResult<TcpStream> {
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    pub fn perform_handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Act One
        let act_one_message = self.noise.act_one()?;
        self.send_message(&act_one_message)?;

        // Act Two
        let act_two_message = self.receive_act_two()?;
        self.noise.act_two(act_two_message.try_into().unwrap())?;

        // Act Three
        let act_three_message = self.noise.act_three()?;
        self.send_message(&act_three_message)?;

        println!("Noise handshake completed successfully!");
        Ok(())
    }

    fn send_message(&mut self, message: &[u8]) -> IoResult<()> {
        self.stream.write_all(message)?;
        self.stream.flush()?;

        Ok(())
    }

    fn receive_act_two(&mut self) -> IoResult<Vec<u8>> {
        let mut act_two_buffer = vec![0u8; ACT_TWO_BUFFER_SIZE];

        match self.stream.read_exact(&mut act_two_buffer) {
            Ok(()) => Ok(act_two_buffer),
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
        let mut read_buffer = vec![0u8; MESSAGE_BUFFER_SIZE];

        loop {
            match self.stream.read(&mut read_buffer) {
                Ok(0) => {
                    println!("Connection closed by peer");
                    break;
                }
                Ok(bytes_read) => {
                    self.message_buffer
                        .extend_from_slice(&read_buffer[..bytes_read]);

                    while let Some(processed_bytes) =
                        self.try_process_next_message(&mut message_count)?
                    {
                        self.message_buffer.drain(..processed_bytes);
                    }
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

    fn try_process_next_message(
        &mut self,
        message_count: &mut usize,
    ) -> Result<Option<usize>, Box<dyn std::error::Error>> {
        // Need at least 18 bytes for the length prefix
        if self.message_buffer.len() < 18 {
            return Ok(None);
        }

        // Step 1: Decrypt the length prefix to get the packet size
        let lc = &self.message_buffer[0..18];
        let packet_length = match self.noise.decrypt_length(lc) {
            Ok(len) => len as usize,
            Err(e) => {
                eprintln!("   ✗ Failed to decrypt length prefix: {}", e);
                return Err(e.into());
            }
        };

        // Step 2: Check if we have the complete encrypted packet
        let encrypted_packet_size = packet_length + 16; // +16 for the MAC
        let total_message_size = 18 + encrypted_packet_size;

        if self.message_buffer.len() < total_message_size {
            // We don't have the complete message yet
            return Ok(None);
        }

        *message_count += 1;
        println!(
            "Message #{} (processing {} bytes from buffer of {} bytes):",
            message_count,
            total_message_size,
            self.message_buffer.len()
        );

        // Step 3: Extract and decrypt the message
        let c = &self.message_buffer[18..total_message_size];

        println!(
            "   Encrypted packet ({} bytes): {}",
            c.len(),
            hex::encode(c)
        );

        self.noise.receive_nonce += 1;
        println!("Decrypt nonce 2: {}", self.noise.receive_nonce);

        // Step 4: Decrypt the packet to get the plaintext
        match self.noise.decrypt_message(c) {
            Ok(plaintext) => {
                println!(
                    "   ✓ Decrypted message ({} bytes): {}",
                    plaintext.len(),
                    hex::encode(&plaintext)
                );

                // Try to handle Lightning message if possible
                self.handle_lightning_message(&plaintext)?;
            }
            Err(e) => {
                eprintln!("   ✗ Failed to decrypt message: {}", e);
                return Err(e.into());
            }
        }

        // Return the number of bytes we processed
        Ok(Some(total_message_size))
    }

    fn handle_lightning_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if plaintext.len() < 2 {
            return Err("Message too short to contain type".into());
        }

        let message_type = MessageType::from_bytes(plaintext);
        match message_type {
            MessageType::Init => {
                let init = self.noise.encrypt_and_format_message(plaintext)?;
                println!(
                    "   Sending init message(size: {}): {}",
                    init.len(),
                    hex::encode(&init)
                );
                self.send_message(&init)?;
            }
            MessageType::Unknown => {
                println!("   Unknown message type: {}", message_type);
            }
            _ => {
                println!("   Message type: {}", message_type);
            }
        }

        Ok(())
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

    pub fn into_buffered(self) -> BufferedNoiseClient {
        BufferedNoiseClient {
            writer: BufWriter::new(self.stream),
        }
    }
}

pub struct BufferedNoiseClient {
    writer: BufWriter<TcpStream>,
}

impl BufferedNoiseClient {
    pub fn send_message(&mut self, slice: IoSlice) -> Result<(), ()> {
        unsafe {
            let nwritten = libc::writev(
                self.writer.get_ref().as_raw_fd(),
                &slice as *const IoSlice as *const _,
                1,
            );

            if nwritten < 0 {
                return Err(());
            }

            Ok(())
        }
    }
}
