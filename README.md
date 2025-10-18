# Noise Protocol Lightning

A Rust implementation of the Noise Protocol Framework for secure communication with Lightning Network nodes. This project implements the `Noise_XK_secp256k1_ChaChaPoly_SHA256` handshake pattern used by the Lightning Network for establishing encrypted connections.

## Overview

This library provides a complete implementation of the Lightning Network's transport layer encryption, enabling secure peer-to-peer communication with Lightning nodes. It implements the three-act handshake protocol and subsequent encrypted messaging as specified in [BOLT #8](https://github.com/lightning/bolts/blob/master/08-transport.md).

## Features

- Full Noise Protocol Framework implementation with XK handshake pattern
- secp256k1 elliptic curve cryptography for key exchange
- ChaCha20-Poly1305 AEAD encryption for message confidentiality and authentication
- SHA-256 for hash operations and HKDF key derivation
- Three-act handshake establishment
- Encrypted message transmission and reception
- Lightning Network message handling
- TCP connection management with configurable timeouts

## Protocol Details

### Handshake Flow

The implementation follows the Lightning Network's three-act handshake:

1. **Act One** (Initiator → Responder): The initiator sends its ephemeral public key
2. **Act Two** (Responder → Initiator): The responder sends its ephemeral public key
3. **Act Three** (Initiator → Responder): The initiator authenticates with its static public key

After the handshake, both parties derive symmetric encryption keys for bidirectional communication.

### Message Format

Encrypted messages use the following format:
- **Length Prefix**: 18 bytes (2-byte length + 16-byte MAC)
- **Encrypted Payload**: Variable length + 16-byte MAC

### Cryptographic Primitives

- **Key Exchange**: secp256k1 ECDH
- **Encryption**: ChaCha20-Poly1305 AEAD
- **Hashing**: SHA-256
- **Key Derivation**: HKDF-SHA256

## Dependencies

- `bitcoin_hashes` - SHA-256 and HKDF implementations
- `chacha20-poly1305` - ChaCha20-Poly1305 AEAD cipher
- `secp256k1` - Elliptic curve operations
- `rand` - Cryptographic random number generation
- `hex` - Hexadecimal encoding/decoding

## Security Considerations

- Uses cryptographically secure random number generation for ephemeral keys
- Implements proper nonce handling to prevent reuse
- Follows Lightning Network's security specifications (BOLT #8)
- All cryptographic operations use well-audited libraries

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [BOLT #8: Encrypted and Authenticated Transport](https://github.com/lightning/bolts/blob/master/08-transport.md)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Lightning Network Specifications](https://github.com/lightning/bolts)

## Acknowledgments

This implementation follows the Lightning Network specification (BOLT #8) for the Noise Protocol handshake and encrypted transport layer.
