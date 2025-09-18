# URICrypt

A Rust library for encrypting URIs while preserving their hierarchical structure and common prefixes.

## Features

- Prefix-Preserving Encryption: URIs with shared paths maintain identical encrypted prefixes, enabling efficient caching and storage
- Plaintext Scheme: URI schemes (like `https://`) remain unencrypted for protocol identification
- Path-Only Support: Can encrypt paths without schemes (e.g., `/path/to/file`)
- Deterministic Encryption: Same inputs always produce the same encrypted output
- URL-Safe Output: Generates clean URLs without padding characters using base64 URL-safe encoding
- Authenticated Encryption: Each component includes a 16-byte SIV for tamper detection

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
uricrypt = "0.1"
```

## Usage

### Basic Example

```rust
use uricrypt::{encrypt_uri, decrypt_uri};

fn main() {
    let uri = "https://example.com/api/v1/users";
    let secret_key = b"your-secret-key-min-32-bytes-recommended";
    let context = b"MyApp-v1.0";

    // Encrypt the URI (scheme remains plaintext)
    let encrypted = encrypt_uri(uri, secret_key, context);
    println!("Encrypted: {}", encrypted);
    // Output: https://<base64-encoded-encrypted-components>

    // Decrypt it back
    let decrypted = decrypt_uri(&encrypted, secret_key, context).unwrap();
    assert_eq!(uri, decrypted);

    // Also works with path-only URIs
    let path = "/api/v1/users";
    let encrypted_path = encrypt_uri(path, secret_key, context);
    println!("Encrypted path: {}", encrypted_path);
    // Output: /<base64-encoded-encrypted-path>
}
```

### Prefix Preservation

URIs sharing common paths will have identical encrypted prefixes:

```rust
let key = b"secret-key";
let ctx = b"app-context";

let uri1 = "https://api.example.com/v1/users/123";
let uri2 = "https://api.example.com/v1/users/456";
let uri3 = "https://api.example.com/v2/posts";

let enc1 = encrypt_uri(uri1, key, ctx);
let enc2 = encrypt_uri(uri2, key, ctx);
let enc3 = encrypt_uri(uri3, key, ctx);

// All three start with "https://" (plaintext scheme)
// enc1 and enc2 share the same encrypted prefix for "api.example.com/v1/users/"
// All three share the encrypted prefix for "api.example.com/"
```

## API Reference

### `encrypt_uri`

```rust
pub fn encrypt_uri(uri: &str, secret_key: &[u8], context: &[u8]) -> String
```

Encrypts a URI while preserving its hierarchical structure and keeping the scheme in plaintext.

Parameters:
- `uri`: The URI to encrypt (with or without scheme)
- `secret_key`: Secret key for encryption (use at least 32 bytes)
- `context`: Additional context for domain separation (e.g., app version)

Returns:
- For URIs with scheme: Plaintext scheme followed by encrypted components
- For path-only URIs: '/' followed by encrypted path components

### `decrypt_uri`

```rust
pub fn decrypt_uri(
    encrypted_uri: &str,
    secret_key: &[u8],
    context: &[u8],
) -> Result<String, String>
```

Decrypts a URI encrypted with `encrypt_uri`.

Parameters:
- `encrypted_uri`: The encrypted URI (with plaintext scheme or path-only format)
- `secret_key`: Same secret key used for encryption
- `context`: Same context used for encryption

Returns: `Ok(String)` with the original URI, or `Err(String)` if authentication fails

## Security Considerations

- Key Management: Use a cryptographically secure random key of at least 16 bytes
- Key Validation: The library validates that key halves are not identical to prevent weak keys
- Context Binding: The context parameter provides domain separation - use it to bind encryption to specific applications or versions
- Deterministic: This is deterministic encryption - identical URIs encrypted with the same key/context produce identical ciphertexts
- Authentication: Each URI component includes a 16-byte authentication tag (SIV) that prevents tampering
- Accumulated State: Each component's SIV is computed from the accumulated hasher state of all previous components
- Plaintext Scheme: URI schemes remain unencrypted for protocol identification
- Algorithm: Uses TurboShake128 (SHA-3 family) for key derivation and stream generation with domain separation

## Use Cases

- Privacy-Preserving Caching: Cache encrypted URLs while maintaining cache hierarchy
- Log Anonymization: Store and analyze sensitive URLs in logs without exposing actual endpoints
- Compliant Data Storage: Meet data residency requirements while maintaining URL structure
