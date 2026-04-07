# MoonBit Crypto

A comprehensive cryptographic library collection for the MoonBit programming language, providing secure and performant implementations of essential cryptographic primitives.

## Overview

MoonBit Crypto aims to provide a robust, modular, and easy-to-use cryptographic ecosystem for MoonBit developers. Inspired by RustCrypto's design philosophy, this project offers individual packages for different cryptographic operations, allowing developers to include only what they need.

## Packages

### Core Components

| Package | Description | Status |
|---------|-------------|--------|
| **mb-getrandom** | Secure random number generation (OS entropy; native + WASM) | Done |
| **mb-chacha** | ChaCha20 and XChaCha20 stream ciphers (RFC 8439) | Done |

### Hash Functions & MACs

| Package | Description | Status |
|---------|-------------|--------|
| **mb-hash** | Cryptographic hash functions (SHA-256, SHA-512) | Done |
| **mb-hmac** | HMAC-SHA256 and HMAC-SHA512 with constant-time verification | Done |

### Application-Level Protocols

| Package | Description | Status |
|---------|-------------|--------|
| **mb-jwt** | JSON Web Tokens (HS256 signing and verification) | Done |

### Planned

| Package | Description |
|---------|-------------|
| **mb-poly** | Poly1305 message authentication |
| **mb-aead** | Authenticated Encryption (ChaCha20-Poly1305, AES-GCM) |
| **mb-kdf** | Key Derivation Functions (HKDF, PBKDF2) |
| **mb-aes** | AES block cipher |
| **mb-ecdh** | Elliptic Curve Diffie-Hellman (X25519, P-256) |

## Installation

Each package can be installed independently using MoonBit's package manager:

```bash
moon add Tigls/mb-hash
moon add Tigls/mb-hmac     # HMAC package
moon add Tigls/mb-jwt
# etc.
```

## Usage Examples

### Generate Random Bytes

```moonbit
fn main {
  let bytes = @lib.getrandom(32)
  match bytes {
    Ok(b) => println("Generated 32 random bytes")
    Err(e) => println("Error: \{e}")
  }
}
```

### Hash Data with SHA-256

```moonbit
fn main {
  // One-shot hashing
  let hash = @sha2.Sha256::digest_string("Hello, MoonBit!")
  let hex = @sha2.hash_to_hex(hash)
  println("SHA-256: \{hex}")

  // Incremental hashing
  let hasher = @sha2.Sha256::new()
  hasher.update(data_part1)
  hasher.update(data_part2)
  let hash = hasher.finalize()
}
```

### HMAC-SHA256

```moonbit
fn main {
  // Generate MAC
  let mac = @hmac.hmac_sha256_string("message", "secret-key")

  // Verify MAC (constant-time comparison)
  let valid = @hmac.verify_hmac_sha256_string("message", "secret-key", mac_to_verify)
}
```

### ChaCha20 Encryption

```moonbit
fn main {
  let cipher = @chacha20.ChaCha20::new(key, nonce) // 32-byte key, 12-byte nonce
  match cipher {
    Ok(c) => {
      let ciphertext = c.encrypt_bytes(plaintext)
      // Decrypt with a fresh cipher instance (same key/nonce)
      let c2 = @chacha20.ChaCha20::new(key, nonce).unwrap()
      let decrypted = c2.decrypt_bytes(ciphertext)
    }
    Err(e) => println("Error: \{e}")
  }
}
```

### XChaCha20 Encryption

```moonbit
fn main {
  // Extended nonce variant (24-byte nonce) - safer for random nonces
  let cipher = @chacha20.XChaCha20::new(key, nonce) // 32-byte key, 24-byte nonce
  match cipher {
    Ok(c) => {
      let ciphertext = c.encrypt_bytes(plaintext)
    }
    Err(e) => println("Error: \{e}")
  }
}
```

### JWT Signing and Verification

```moonbit
fn main {
  let payload = "{\"sub\":\"1234567890\",\"name\":\"John\",\"iat\":1516239022}"
  let secret = "my-secret-key"

  // Sign
  let token = @jwt.sign(payload, secret)

  // Verify and decode
  match @jwt.verify(token, secret) {
    Ok(decoded_payload) => println("Payload: \{decoded_payload}")
    Err(e) => println("Invalid token: \{e}")
  }

  // Decode without verification (for inspecting tokens)
  let header = @jwt.decode_header(token)
  let payload = @jwt.decode(token)
}
```

## Dependency Graph

```
mb-jwt --> mb-hmac --> mb-hash
mb-chacha --> mb-getrandom
```

## Security Considerations

**Important**: These libraries are in development and have not been audited. Do not use in production systems yet.

- All implementations aim to be constant-time where applicable
- Test vectors from relevant RFCs and NIST standards are included
- HMAC verification uses constant-time comparison to prevent timing attacks
- WebAssembly support includes secure random generation via Web Crypto API

## Development

### Build and Test

```bash
moon build                # Build all packages
moon test --target native # Run tests with native backend
moon test --target js     # Run tests with JavaScript backend
```

> **Note:** Bare `moon test` (wasm-gc target) will fail for packages with custom host imports (e.g., mb-getrandom).
> Use `--target native` or `--target js` instead. For wasm-gc testing, see each package's README.

### Platform Support

| Target | Random | Hash | HMAC | ChaCha20 | JWT |
|--------|--------|------|------|----------|-----|
| Native | C FFI (`/dev/urandom`, `BCryptGenRandom`) | Pure MoonBit | Pure MoonBit | Pure MoonBit | Pure MoonBit |
| JS/WASM | Web Crypto API / Node.js `crypto` | Pure MoonBit | Pure MoonBit | Pure MoonBit | Pure MoonBit |

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

All packages are licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by the [RustCrypto](https://github.com/RustCrypto) project
- Test vectors from IETF RFCs and NIST standards

## Security Reporting

If you discover a security vulnerability, please email security@moonbitlang.org with details. Do not open a public issue.

## Links

- [MoonBit Language](https://www.moonbitlang.org/)
- [Documentation](https://docs.moonbitlang.org/)
- [Community Discord](https://discord.gg/moonbit)
