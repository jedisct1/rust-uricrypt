use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    TurboShake128, TurboShake128Core,
};

/// Splits a URI into its scheme and hierarchical components.
/// Returns (scheme_with_separator, components) where scheme includes "://" if present.
/// For path-only URIs (no scheme), returns (None, components).
fn split_uri(uri: &str) -> (Option<&str>, Vec<&str>) {
    // Check if this is a URI with a scheme
    if let Some(scheme_end) = uri.find("://") {
        let scheme = &uri[..scheme_end + 3]; // Include "://"
        let rest = &uri[scheme_end + 3..];

        if rest.is_empty() {
            return (Some(scheme), vec![]);
        }

        let mut components = vec![];
        let mut start = 0;
        for (i, ch) in rest.char_indices() {
            if ch == '/' {
                components.push(&rest[start..=i]);
                start = i + 1;
            }
        }

        if start < rest.len() {
            components.push(&rest[start..]);
        }

        return (Some(scheme), components);
    }

    // No scheme found - treat as path-only URI
    if uri.is_empty() {
        return (None, vec![]);
    }

    let mut components = vec![];
    let mut start = 0;

    // Handle absolute paths that start with '/'
    let path_start = if uri.starts_with('/') { 1 } else { 0 };
    let path = &uri[path_start..];

    // If it was an absolute path, add the leading slash as the first component
    if path_start == 1 && !path.is_empty() {
        components.push("/");
    } else if path_start == 1 && path.is_empty() {
        // Just a single "/"
        return (None, vec!["./"]);
    }

    // Split the rest of the path
    if !path.is_empty() {
        for (i, ch) in path.char_indices() {
            if ch == '/' {
                if start < i {
                    components.push(&path[start..=i]);
                } else if start == i {
                    // Double slash - preserve it
                    components.push(&path[i..=i]);
                }
                start = i + 1;
            }
        }

        if start < path.len() {
            components.push(&path[start..]);
        } else if start == path.len() && path.ends_with('/') {
            // Already handled by including the slash in the previous component
        }
    }

    // If we have no components, treat it as current directory
    if components.is_empty() && !uri.is_empty() {
        components.push(uri);
    }

    (None, components)
}

/// Performs XOR operation in-place on data using a keystream.
///
/// Modifies the data buffer directly by XORing each byte with the corresponding
/// byte from the keystream. This is used for stream cipher encryption/decryption.
///
/// # Arguments
///
/// * `data` - The mutable byte slice to XOR (modified in-place)
/// * `keystream` - The keystream bytes to XOR with
///
/// # Note
///
/// Only processes up to the minimum length of data and keystream.
#[inline]
fn xor_in_place(data: &mut [u8], keystream: &[u8]) {
    for (d, k) in data.iter_mut().zip(keystream.iter()) {
        *d ^= k;
    }
}

/// Size of the Synthetic Initialization Vector (SIV) in bytes.
/// Used for authentication tags on each URI component.
const SIV_SIZE: usize = 16;

/// Encrypts a URI while preserving its hierarchical structure and scheme.
///
/// This function keeps the URI scheme (e.g., "https://") in plaintext and encrypts
/// each path component independently. URIs with common prefixes share encrypted
/// prefixes. Each component is authenticated with a Synthetic Initialization Vector (SIV)
/// computed from the accumulated hasher state of all previous components.
///
/// For path-only URIs (no scheme), the entire path is encrypted and returned as
/// base64-encoded ciphertext.
///
/// # Arguments
///
/// * `uri` - The URI to encrypt (with or without scheme)
/// * `secret_key` - Secret key for encryption
/// * `context` - Additional context data for domain separation
///
/// # Returns
///
/// A string with the plaintext scheme (if present) followed by URL-safe base64 encoded encrypted components.
/// For path-only URIs, returns just the base64-encoded encrypted path.
///
/// # Security
///
/// - Uses TurboShake128 for key derivation and stream generation
/// - Each component has a 16-byte authentication tag (SIV)
/// - SIVs are computed from accumulated hasher state of all previous components
/// - Deterministic: same inputs always produce the same output
/// - Prefix-preserving: common URI prefixes share encrypted prefixes
/// - Scheme remains plaintext for protocol identification (when present)
///
/// # Example
///
/// ```
/// use uricrypt::encrypt_uri;
///
/// // With scheme
/// let encrypted = encrypt_uri(
///     "https://example.com/path",
///     b"secret_key",
///     b"app_context"
/// );
///
/// // Without scheme (path-only)
/// let encrypted = encrypt_uri(
///     "/path/to/file",
///     b"secret_key",
///     b"app_context"
/// );
/// ```
pub fn encrypt_uri(uri: &str, secret_key: &[u8], context: &[u8]) -> String {
    // Check if key has even length and both halves are identical
    if secret_key.len() >= 2 && secret_key.len() % 2 == 0 {
        let mid = secret_key.len() / 2;
        let (first_half, second_half) = secret_key.split_at(mid);
        if first_half == second_half {
            panic!("Key validation failed: both halves of the key are identical");
        }
    }

    let (scheme, uri_parts) = split_uri(uri);

    // If no components, return empty string
    if uri_parts.is_empty() {
        // If there was a scheme but no components, return just the scheme
        if let Some(scheme) = scheme {
            return scheme.to_string();
        }
        return String::new();
    }

    let mut encrypted_uri = Vec::with_capacity(uri.len() * 2);

    // Create base hasher with constant parts (secret key and context)
    let mut base_hasher = TurboShake128::from_core(TurboShake128Core::new(0x1F));
    base_hasher.update(&[secret_key.len() as u8]);
    base_hasher.update(secret_key);
    base_hasher.update(&[context.len() as u8]);
    base_hasher.update(context);

    let mut components_hasher = base_hasher.clone();
    components_hasher.update(b"IV");
    let mut base_keystream_hasher = base_hasher.clone();
    base_keystream_hasher.update(b"KS");

    for part in uri_parts {
        let part_bytes = part.as_bytes();

        // Calculate padding for base64 alignment
        let total_unpadded = SIV_SIZE + part_bytes.len();
        let padding = (3 - (total_unpadded % 3)) % 3;

        // Update the hasher with this component's data
        components_hasher.update(part_bytes);

        let mut siv = [0u8; SIV_SIZE];
        components_hasher.clone().finalize_xof().read(&mut siv);

        // Generate keystream and encrypt
        let mut keystream_hasher = base_keystream_hasher.clone();
        keystream_hasher.update(&siv);

        let mut encrypted_part = vec![0u8; part_bytes.len() + padding];
        encrypted_part[..part_bytes.len()].copy_from_slice(part_bytes);

        let mut keystream = vec![0u8; encrypted_part.len()];
        keystream_hasher.finalize_xof().read(&mut keystream);

        xor_in_place(&mut encrypted_part, &keystream);

        encrypted_uri.extend_from_slice(&siv);
        encrypted_uri.extend_from_slice(&encrypted_part);
    }

    // Format output based on whether there's a scheme
    if let Some(scheme) = scheme {
        format!("{}{}", scheme, URL_SAFE_NO_PAD.encode(encrypted_uri))
    } else {
        // Prepend '/' to indicate this is a path-only URI
        format!("/{}", URL_SAFE_NO_PAD.encode(encrypted_uri))
    }
}

/// Decrypts a URI that was encrypted with `encrypt_uri`.
///
/// Expects either:
/// - A URI with a plaintext scheme followed by base64-encoded encrypted components
/// - A path-only URI that is entirely base64-encoded
///
/// Validates the authentication tags (SIVs) for each component (computed from
/// accumulated hasher state) to ensure integrity and authenticity before returning
/// the decrypted URI.
///
/// # Arguments
///
/// * `encrypted_uri` - The encrypted URI (with or without plaintext scheme)
/// * `secret_key` - Secret key used for encryption (must match)
/// * `context` - Context data used for encryption (must match)
///
/// # Returns
///
/// * `Ok(String)` - The decrypted URI if authentication succeeds
/// * `Err(String)` - Error message if decryption or authentication fails
///
/// # Errors
///
/// Will return an error if:
/// - The base64 encoding is invalid
/// - The encrypted data is malformed
/// - Authentication fails (wrong key/context)
/// - No valid components can be recovered
///
/// # Example
///
/// ```
/// use uricrypt::{encrypt_uri, decrypt_uri};
///
/// // With scheme
/// let encrypted_uri = encrypt_uri(
///     "https://example.com",
///     b"secret_key",
///     b"app_context"
/// );
///
/// let decrypted = decrypt_uri(
///     &encrypted_uri,
///     b"secret_key",
///     b"app_context"
/// ).unwrap();
///
/// // Without scheme (path-only)
/// let encrypted_path = encrypt_uri(
///     "/path/to/file",
///     b"secret_key",
///     b"app_context"
/// );
///
/// let decrypted = decrypt_uri(
///     &encrypted_path,
///     b"secret_key",
///     b"app_context"
/// ).unwrap();
/// ```
pub fn decrypt_uri(
    encrypted_uri: &str,
    secret_key: &[u8],
    context: &[u8],
) -> Result<String, String> {
    // Check if key has even length and both halves are identical
    if secret_key.len() >= 2 && secret_key.len() % 2 == 0 {
        let mid = secret_key.len() / 2;
        let (first_half, second_half) = secret_key.split_at(mid);
        if first_half == second_half {
            return Err("Key validation failed: both halves of the key are identical".to_string());
        }
    }

    // Check if this is a path-only URI (starts with '/')
    let (scheme, encrypted_part) = if let Some(stripped) = encrypted_uri.strip_prefix('/') {
        // Path-only URI - skip the leading '/'
        (None, stripped)
    } else if let Some(scheme_end) = encrypted_uri.find("://") {
        // URI with scheme
        let scheme = &encrypted_uri[..scheme_end + 3];
        let encrypted = &encrypted_uri[scheme_end + 3..];

        // If nothing after scheme, just return the scheme
        if encrypted.is_empty() {
            return Ok(scheme.to_string());
        }

        (Some(scheme), encrypted)
    } else {
        // Invalid format - neither starts with '/' nor contains '://'
        return Err("Invalid encrypted URI format: must start with '/' for paths or contain '://' for URIs with schemes".to_string());
    };

    // Decode the encrypted part
    let encrypted_bytes = URL_SAFE_NO_PAD
        .decode(encrypted_part)
        .map_err(|e| format!("Invalid base64: {}", e))?;

    let mut decrypted_components = Vec::<String>::new();
    let mut pos = 0;

    // Create base hasher with constant parts (secret key and context)
    let mut base_hasher = TurboShake128::from_core(TurboShake128Core::new(0x1F));
    base_hasher.update(&[secret_key.len() as u8]);
    base_hasher.update(secret_key);
    base_hasher.update(&[context.len() as u8]);
    base_hasher.update(context);

    // This hasher will accumulate state from previous components
    let mut components_hasher = base_hasher.clone();
    components_hasher.update(b"IV");

    let mut base_keystream_hasher = base_hasher.clone();
    base_keystream_hasher.update(b"KS");

    while pos < encrypted_bytes.len() {
        if pos + SIV_SIZE > encrypted_bytes.len() {
            return Err("Malformed encrypted data: incomplete SIV".to_string());
        }

        let siv = &encrypted_bytes[pos..pos + SIV_SIZE];
        let component_start = pos + SIV_SIZE;
        pos += SIV_SIZE;

        let mut keystream_hasher = base_keystream_hasher.clone();
        keystream_hasher.update(siv);
        let mut reader = keystream_hasher.finalize_xof();

        let mut component = Vec::with_capacity(64);

        // Decrypt bytes until we find '/' or reach the end
        while pos < encrypted_bytes.len() {
            let mut keystream_byte = [0u8; 1];
            reader.read(&mut keystream_byte);

            let decrypted_byte = encrypted_bytes[pos] ^ keystream_byte[0];
            pos += 1;

            if decrypted_byte == 0 {
                // Skip padding bytes
                continue;
            }

            component.push(decrypted_byte);

            if decrypted_byte == b'/' {
                // Found end of component, consume any remaining padding
                let bytes_read = pos - component_start;
                let total_len = SIV_SIZE + bytes_read;
                let padding_needed = (3 - (total_len % 3)) % 3;

                for _ in 0..padding_needed {
                    if pos >= encrypted_bytes.len() {
                        return Err("Authentication failed".to_string());
                    }
                    let mut keystream_byte = [0u8; 1];
                    reader.read(&mut keystream_byte);
                    if (encrypted_bytes[pos] ^ keystream_byte[0]) != 0 {
                        return Err("Authentication failed".to_string());
                    }
                    pos += 1;
                }
                break;
            }
        }

        // Validate the component
        if component.is_empty() {
            return Err("Authentication failed".to_string());
        }

        // Update the hasher with this component's data
        components_hasher.update(&component);

        // Compute the expected SIV for this component based on accumulated state
        let mut expected_siv = [0u8; SIV_SIZE];
        components_hasher
            .clone()
            .finalize_xof()
            .read(&mut expected_siv);

        // Verify the SIV matches - this ensures proper chaining
        if expected_siv != siv {
            return Err("Authentication failed".to_string());
        }

        // Check UTF-8 validity
        match std::str::from_utf8(&component) {
            Ok(comp_str) => {
                decrypted_components.push(comp_str.to_string());
            }
            Err(_) => {
                // Invalid UTF-8 means decryption failed
                return Err("Authentication failed".to_string());
            }
        }
    }

    if decrypted_components.is_empty() {
        return Err("Authentication failed".to_string());
    }

    // Join all decrypted components
    let decrypted_uri = decrypted_components.join("");

    // Format output based on whether there was a scheme
    if let Some(scheme) = scheme {
        Ok(format!("{}{}", scheme, decrypted_uri))
    } else {
        Ok(decrypted_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_uri() {
        let (scheme, components) = split_uri("https://example.com");
        assert_eq!(scheme, Some("https://"));
        assert_eq!(components, vec!["example.com"]);
    }

    #[test]
    fn test_path_only_absolute() {
        let (scheme, components) = split_uri("/path/to/file");
        assert_eq!(scheme, None);
        assert_eq!(components, vec!["/", "path/", "to/", "file"]);
    }

    #[test]
    fn test_path_only_relative() {
        let (scheme, components) = split_uri("path/to/file");
        assert_eq!(scheme, None);
        assert_eq!(components, vec!["path/", "to/", "file"]);
    }

    #[test]
    fn test_path_only_single_slash() {
        let (scheme, components) = split_uri("/");
        assert_eq!(scheme, None);
        assert_eq!(components, vec!["./"]);
    }

    #[test]
    fn test_path_only_single_component() {
        let (scheme, components) = split_uri("file.txt");
        assert_eq!(scheme, None);
        assert_eq!(components, vec!["file.txt"]);
    }

    #[test]
    fn test_uri_with_trailing_slash() {
        let (scheme, components) = split_uri("https://example.com/");
        assert_eq!(scheme, Some("https://"));
        assert_eq!(components, vec!["example.com/"]);
    }

    #[test]
    fn test_uri_with_path() {
        let (scheme, components) = split_uri("https://example.com/a/b/c");
        assert_eq!(scheme, Some("https://"));
        assert_eq!(components, vec!["example.com/", "a/", "b/", "c"]);
    }

    #[test]
    fn test_uri_with_path_and_trailing_slash() {
        let (scheme, components) = split_uri("https://example.com/a/b/c/");
        assert_eq!(scheme, Some("https://"));
        assert_eq!(components, vec!["example.com/", "a/", "b/", "c/"]);
    }

    #[test]
    fn test_encrypt_uri_basic() {
        let uri = "https://example.com";
        let secret_key = b"test_key";
        let context = b"test_context";
        let encrypted = encrypt_uri(uri, secret_key, context);

        // Check that scheme is preserved
        assert!(encrypted.starts_with("https://"));

        // Get the encrypted part after scheme
        let encrypted_part = &encrypted["https://".len()..];

        // Check that encrypted part is valid base64 (URL-safe chars only)
        assert!(encrypted_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

        // Check that there are no padding characters
        assert!(!encrypted_part.contains('='));

        // Check length with new padding scheme (SIV + component must be multiple of 3):
        // "example.com" = 11 bytes, SIV = 16 bytes, total = 27 bytes (divisible by 3)
        // Base64 encoding: 27 bytes * 4/3 = 36 base64 chars
        assert_eq!(encrypted_part.len(), 36);
    }

    #[test]
    fn test_encrypt_uri_deterministic() {
        let uri = "https://example.com/test";
        let secret_key = b"my_secret";
        let context = b"test_ctx";

        let encrypted1 = encrypt_uri(uri, secret_key, context);
        let encrypted2 = encrypt_uri(uri, secret_key, context);

        // Same input should produce same output
        assert_eq!(encrypted1, encrypted2);
    }

    #[test]
    fn test_encrypt_uri_different_keys() {
        let uri = "https://example.com";
        let key1 = b"key1";
        let key2 = b"key2";
        let context = b"test_ctx";

        let encrypted1 = encrypt_uri(uri, key1, context);
        let encrypted2 = encrypt_uri(uri, key2, context);

        // Different keys should produce different outputs
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_xor_in_place() {
        let mut data = vec![0xFF, 0x00, 0xAA, 0x55];
        let keystream = vec![0x00, 0xFF, 0x55, 0xAA];
        xor_in_place(&mut data, &keystream);
        assert_eq!(data, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_prefix_preservation() {
        let secret_key = b"test_secret_key";
        let context = b"test_ctx";

        // Two URIs that share the same prefix components
        let uri1 = "https://example.com/path/to/resource";
        let uri2 = "https://example.com/path/to/other";
        let uri3 = "https://example.com/different/path";

        let encrypted1 = encrypt_uri(uri1, secret_key, context);
        let encrypted2 = encrypt_uri(uri2, secret_key, context);
        let encrypted3 = encrypt_uri(uri3, secret_key, context);

        // All should start with the same scheme
        assert!(encrypted1.starts_with("https://"));
        assert!(encrypted2.starts_with("https://"));
        assert!(encrypted3.starts_with("https://"));

        // Get encrypted parts after scheme
        let enc1_part = &encrypted1["https://".len()..];
        let enc2_part = &encrypted2["https://".len()..];
        let enc3_part = &encrypted3["https://".len()..];

        // Calculate expected prefix lengths with new padding scheme
        // They share: "example.com/" (12 bytes) and "path/" (5 bytes) and "to/" (3 bytes)
        // Component 1: "example.com/" = 12 bytes, SIV = 16, total = 28, need 2 padding -> 30 bytes
        // Component 2: "path/" = 5 bytes, SIV = 16, total = 21 (divisible by 3) -> 21 bytes
        // Component 3: "to/" = 3 bytes, SIV = 16, total = 19, need 2 padding -> 21 bytes
        // Total shared prefix in bytes: 30 + 21 + 21 = 72 bytes
        // In base64: 72 bytes * 4/3 = 96 base64 characters

        let shared_prefix_len_1_2 = 96;

        // uri1 and uri2 should share the same encrypted prefix
        assert_eq!(
            &enc1_part[..shared_prefix_len_1_2],
            &enc2_part[..shared_prefix_len_1_2],
            "URI1 and URI2 should share the same encrypted prefix for 'example.com/path/to/'"
        );

        // Calculate expected prefix length for all three URIs
        // They share: "example.com/" (12 bytes)
        // Component 1: "example.com/" = 12 bytes, SIV = 16, total = 28, need 2 padding -> 30 bytes
        // In base64: 30 bytes * 4/3 = 40 base64 characters

        let shared_prefix_len_all = 40;

        // All three URIs should share the prefix for "example.com/"
        assert_eq!(
            &enc1_part[..shared_prefix_len_all],
            &enc3_part[..shared_prefix_len_all],
            "URI1 and URI3 should share the same encrypted prefix for 'example.com/'"
        );

        assert_eq!(
            &enc2_part[..shared_prefix_len_all],
            &enc3_part[..shared_prefix_len_all],
            "URI2 and URI3 should share the same encrypted prefix for 'example.com/'"
        );

        // The parts after the shared prefix should be different
        assert_ne!(
            &enc1_part[shared_prefix_len_1_2..],
            &enc2_part[shared_prefix_len_1_2..],
            "URI1 and URI2 should differ after their shared prefix"
        );

        assert_ne!(
            &enc1_part[shared_prefix_len_all..],
            &enc3_part[shared_prefix_len_all..],
            "URI1 and URI3 should differ after their shared prefix"
        );
    }

    #[test]
    fn test_decrypt_uri_basic() {
        let uri = "https://example.com";
        let secret_key = b"test_key";
        let context = b"test_context";

        let encrypted = encrypt_uri(uri, secret_key, context);
        let decrypted = decrypt_uri(&encrypted, secret_key, context).unwrap();

        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_decrypt_uri_with_slash() {
        let uri = "https://example.com/";
        let secret_key = b"test_key";
        let context = b"test_context";

        let encrypted = encrypt_uri(uri, secret_key, context);
        let decrypted = decrypt_uri(&encrypted, secret_key, context).unwrap();

        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_decrypt_uri_with_path() {
        let uri = "https://example.com/a/b/c";
        let secret_key = b"test_key";
        let context = b"test_context";

        let encrypted = encrypt_uri(uri, secret_key, context);
        let decrypted = decrypt_uri(&encrypted, secret_key, context).unwrap();

        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_decrypt_uri_with_path_trailing_slash() {
        let uri = "https://example.com/a/b/c/";
        let secret_key = b"test_key";
        let context = b"test_context";

        let encrypted = encrypt_uri(uri, secret_key, context);
        let decrypted = decrypt_uri(&encrypted, secret_key, context).unwrap();

        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_round_trip_various_uris() {
        let test_cases = vec![
            "https://example.com",
            "https://example.com/",
            "https://example.com/path",
            "https://example.com/path/",
            "https://example.com/a/b/c/d/e",
            "https://subdomain.example.com/path/to/resource",
        ];

        let secret_key = b"my_secret_key";
        let context = b"test_context";

        for uri in test_cases {
            let encrypted = encrypt_uri(uri, secret_key, context);
            let decrypted = decrypt_uri(&encrypted, secret_key, context).unwrap();
            assert_eq!(uri, decrypted, "Round-trip failed for: {}", uri);
        }
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let uri = "https://example.com";
        let encrypt_key = b"key1";
        let decrypt_key = b"key2";
        let context = b"test_context";

        let encrypted = encrypt_uri(uri, encrypt_key, context);
        let result = decrypt_uri(&encrypted, decrypt_key, context);

        // Debug print
        if let Ok(decrypted) = &result {
            println!(
                "Unexpected successful decryption with wrong key: {}",
                decrypted
            );
        }

        assert!(result.is_err(), "Decryption should fail with wrong key");
        if result.is_err() {
            assert!(result.unwrap_err().contains("Authentication failed"));
        }
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let result = decrypt_uri("https://not@valid#base64", b"key", b"ctx");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid base64"));
    }

    #[test]
    fn test_component_reordering_attack() {
        // This test verifies that components cannot be reordered to create unauthorized URIs
        // The SIV chain validation should prevent mixing components from different URIs
        let secret_key = b"test_key";
        let context = b"test_context";

        // Create two URIs with similar structure
        let uri1 = "https://a.com/b/c";
        let uri2 = "https://x.com/y/z";

        let encrypted1 = encrypt_uri(uri1, secret_key, context);
        let encrypted2 = encrypt_uri(uri2, secret_key, context);

        // Extract and decode the encrypted parts
        let enc1_bytes = URL_SAFE_NO_PAD
            .decode(&encrypted1[encrypted1.find("://").unwrap() + 3..])
            .unwrap();
        let enc2_bytes = URL_SAFE_NO_PAD
            .decode(&encrypted2[encrypted2.find("://").unwrap() + 3..])
            .unwrap();

        // To properly test component reordering, we need to find component boundaries
        // Components are: SIV (16 bytes) + encrypted_component + padding

        // Helper to find component boundaries
        fn find_component_boundaries(
            encrypted_bytes: &[u8],
            secret_key: &[u8],
            context: &[u8],
        ) -> Vec<usize> {
            let mut boundaries = vec![0];
            let mut pos = 0;

            // Set up the hasher like in decrypt_uri
            let mut base_hasher = TurboShake128::from_core(TurboShake128Core::new(0x1F));
            base_hasher.update(&[secret_key.len() as u8]);
            base_hasher.update(secret_key);
            base_hasher.update(&[context.len() as u8]);
            base_hasher.update(context);

            let mut base_keystream_hasher = base_hasher.clone();
            base_keystream_hasher.update(b"KS");

            while pos < encrypted_bytes.len() {
                if pos + SIV_SIZE > encrypted_bytes.len() {
                    break;
                }

                let siv = &encrypted_bytes[pos..pos + SIV_SIZE];
                pos += SIV_SIZE;

                let mut keystream_hasher = base_keystream_hasher.clone();
                keystream_hasher.update(siv);
                let mut reader = keystream_hasher.finalize_xof();

                // Decrypt to find the component end
                while pos < encrypted_bytes.len() {
                    let mut keystream_byte = [0u8; 1];
                    reader.read(&mut keystream_byte);
                    let decrypted_byte = encrypted_bytes[pos] ^ keystream_byte[0];
                    pos += 1;

                    if decrypted_byte == b'/' {
                        // Found delimiter, consume padding
                        let component_start = boundaries.last().unwrap() + SIV_SIZE;
                        let bytes_read = pos - component_start;
                        let total_len = SIV_SIZE + bytes_read;
                        let padding = (3 - (total_len % 3)) % 3;

                        for _ in 0..padding {
                            if pos >= encrypted_bytes.len() {
                                break;
                            }
                            reader.read(&mut keystream_byte);
                            pos += 1;
                        }
                        boundaries.push(pos);
                        break;
                    }
                }
            }

            boundaries
        }

        let boundaries1 = find_component_boundaries(&enc1_bytes, secret_key, context);
        let boundaries2 = find_component_boundaries(&enc2_bytes, secret_key, context);

        // Now attempt to create a forged URI by mixing components
        // Take first component from uri2 (x.com/) and second component from uri1 (/b/)
        if boundaries1.len() >= 3 && boundaries2.len() >= 2 {
            let mut forged = Vec::new();

            // Take first component from uri2
            forged.extend_from_slice(&enc2_bytes[boundaries2[0]..boundaries2[1]]);

            // Take second component from uri1
            forged.extend_from_slice(&enc1_bytes[boundaries1[1]..boundaries1[2]]);

            // Try to decrypt the forged URI
            let forged_uri = format!("https://{}", URL_SAFE_NO_PAD.encode(&forged));
            let result = decrypt_uri(&forged_uri, secret_key, context);

            // This should fail because the SIV chain is broken
            // The second component's SIV was computed with uri1's first component,
            // but we're trying to use it after uri2's first component
            assert!(
                result.is_err(),
                "Forged URI should fail authentication but got: {:?}",
                result
            );
        }

        // Verify normal decryption still works
        assert_eq!(decrypt_uri(&encrypted1, secret_key, context).unwrap(), uri1);
        assert_eq!(decrypt_uri(&encrypted2, secret_key, context).unwrap(), uri2);
    }

    #[test]
    fn test_decrypt_truncated_data() {
        let uri = "https://example.com";
        let secret_key = b"test_key";
        let context = b"test_context";

        let encrypted = encrypt_uri(uri, secret_key, context);
        // Truncate the encrypted data
        let truncated = &encrypted[..20];

        let result = decrypt_uri(truncated, secret_key, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_contexts() {
        let uri = "https://example.com";
        let secret_key = b"test_key";
        let context1 = b"context1";
        let context2 = b"context2";

        let encrypted1 = encrypt_uri(uri, secret_key, context1);
        let encrypted2 = encrypt_uri(uri, secret_key, context2);

        // Same URI and key but different contexts should produce different outputs
        assert_ne!(encrypted1, encrypted2);

        // Decrypting with wrong context should fail
        let result = decrypt_uri(&encrypted1, secret_key, context2);
        assert!(result.is_err());

        // Decrypting with correct context should succeed
        let result = decrypt_uri(&encrypted1, secret_key, context1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), uri);
    }

    #[test]
    fn test_siv_state_accumulation() {
        // Test that SIVs are properly computed from accumulated state - URIs with same prefixes
        // should have identical encrypted prefixes up to the point of divergence
        let secret_key = b"test_key";
        let context = b"test_context";

        // Three URIs with varying shared components
        let uri1 = "https://example.com/path1/sub1";
        let uri2 = "https://example.com/path1/sub2";
        let uri3 = "https://example.com/path2/sub1";

        let enc1 = encrypt_uri(uri1, secret_key, context);
        let enc2 = encrypt_uri(uri2, secret_key, context);
        let enc3 = encrypt_uri(uri3, secret_key, context);

        // All should have plaintext scheme
        assert!(enc1.starts_with("https://"));
        assert!(enc2.starts_with("https://"));
        assert!(enc3.starts_with("https://"));

        // Get encrypted parts after scheme
        let enc1_part = &enc1["https://".len()..];
        let enc2_part = &enc2["https://".len()..];
        let enc3_part = &enc3["https://".len()..];

        // Decode from base64 to compare raw bytes
        let bytes1 = URL_SAFE_NO_PAD.decode(enc1_part).unwrap();
        let bytes2 = URL_SAFE_NO_PAD.decode(enc2_part).unwrap();
        let bytes3 = URL_SAFE_NO_PAD.decode(enc3_part).unwrap();

        // Calculate where the first component ends
        // Component 1: "example.com/" = 12 bytes, SIV = 16, total = 28, need 2 padding -> 30 bytes
        let first_component_len = 30;

        // All three should share first component - should be identical up to that point
        assert_eq!(
            &bytes1[..first_component_len],
            &bytes2[..first_component_len],
            "URI1 and URI2 should have identical encrypted prefix for 'example.com/'"
        );

        assert_eq!(
            &bytes1[..first_component_len],
            &bytes3[..first_component_len],
            "URI1 and URI3 should have identical encrypted prefix for 'example.com/'"
        );

        // Calculate where second component ends
        // Component 2 for uri1 and uri2: "path1/" = 6 bytes, SIV = 16, total = 22, need 2 padding -> 24 bytes
        let first_two_components_len = first_component_len + 24;

        // uri1 and uri2 should share first two components (including "path1/")
        assert_eq!(
            &bytes1[..first_two_components_len],
            &bytes2[..first_two_components_len],
            "URI1 and URI2 should have identical encrypted prefix for 'example.com/path1/'"
        );

        // uri1 and uri3 should diverge after first component (different second component)
        let component2_start = first_component_len;
        let component2_siv_end = component2_start + SIV_SIZE;

        assert_ne!(
            &bytes1[component2_start..component2_siv_end],
            &bytes3[component2_start..component2_siv_end],
            "URI1 and URI3 should have different SIVs for their second component ('path1/' vs 'path2/')"
        );

        // Verify all can be decrypted correctly
        assert_eq!(decrypt_uri(&enc1, secret_key, context).unwrap(), uri1);
        assert_eq!(decrypt_uri(&enc2, secret_key, context).unwrap(), uri2);
        assert_eq!(decrypt_uri(&enc3, secret_key, context).unwrap(), uri3);
    }

    #[test]
    fn test_path_only_encryption() {
        let secret_key = b"test_key";
        let context = b"test_context";

        // Test absolute path
        let path1 = "/path/to/file";
        let encrypted1 = encrypt_uri(path1, secret_key, context);

        // Should start with '/' followed by base64
        assert!(encrypted1.starts_with('/'));
        assert!(!encrypted1.contains("://"));
        // Check the base64 part after the '/'
        assert!(encrypted1[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

        // Should decrypt correctly
        let decrypted1 = decrypt_uri(&encrypted1, secret_key, context).unwrap();
        assert_eq!(decrypted1, path1);

        // Test relative path
        let path2 = "path/to/file";
        let encrypted2 = encrypt_uri(path2, secret_key, context);

        assert!(encrypted2.starts_with('/'));
        assert!(!encrypted2.contains("://"));

        let decrypted2 = decrypt_uri(&encrypted2, secret_key, context).unwrap();
        assert_eq!(decrypted2, path2);

        // Test single file
        let path3 = "file.txt";
        let encrypted3 = encrypt_uri(path3, secret_key, context);

        assert!(encrypted3.starts_with('/'));
        assert!(!encrypted3.contains("://"));

        let decrypted3 = decrypt_uri(&encrypted3, secret_key, context).unwrap();
        assert_eq!(decrypted3, path3);
    }

    #[test]
    fn test_path_only_prefix_preservation() {
        let secret_key = b"test_key";
        let context = b"test_context";

        // Paths with shared prefixes
        let path1 = "/shared/path/file1.txt";
        let path2 = "/shared/path/file2.txt";
        let path3 = "/shared/other/file.txt";

        let enc1 = encrypt_uri(path1, secret_key, context);
        let enc2 = encrypt_uri(path2, secret_key, context);
        let enc3 = encrypt_uri(path3, secret_key, context);

        // All should start with '/' (no scheme)
        assert!(enc1.starts_with('/'));
        assert!(enc2.starts_with('/'));
        assert!(enc3.starts_with('/'));
        assert!(!enc1.contains("://"));
        assert!(!enc2.contains("://"));
        assert!(!enc3.contains("://"));

        // Decode to compare prefixes (skip the leading '/')
        let bytes1 = URL_SAFE_NO_PAD.decode(&enc1[1..]).unwrap();
        let bytes2 = URL_SAFE_NO_PAD.decode(&enc2[1..]).unwrap();
        let bytes3 = URL_SAFE_NO_PAD.decode(&enc3[1..]).unwrap();

        // Calculate expected shared prefix for path1 and path2
        // They share: "/" (1 byte), "shared/" (7 bytes), and "path/" (5 bytes)
        // Component 1: "/" = 1 byte, SIV = 16, total = 17, need 1 padding -> 18 bytes
        // Component 2: "shared/" = 7 bytes, SIV = 16, total = 23, need 1 padding -> 24 bytes
        // Component 3: "path/" = 5 bytes, SIV = 16, total = 21 (divisible by 3) -> 21 bytes
        let shared_len_1_2 = 18 + 24 + 21; // 63 bytes

        assert_eq!(
            &bytes1[..shared_len_1_2],
            &bytes2[..shared_len_1_2],
            "Path1 and Path2 should share encrypted prefix"
        );

        // Path1/2 and Path3 should share less (only "/" and "shared/")
        let shared_len_all = 18 + 24; // 42 bytes

        assert_eq!(
            &bytes1[..shared_len_all],
            &bytes3[..shared_len_all],
            "All paths should share '/' and 'shared/' prefix"
        );

        // Verify all decrypt correctly
        assert_eq!(decrypt_uri(&enc1, secret_key, context).unwrap(), path1);
        assert_eq!(decrypt_uri(&enc2, secret_key, context).unwrap(), path2);
        assert_eq!(decrypt_uri(&enc3, secret_key, context).unwrap(), path3);
    }

    #[test]
    fn test_path_only_wrong_key() {
        let path = "/secret/path/file.txt";
        let encrypt_key = b"key1";
        let decrypt_key = b"key2";
        let context = b"test_context";

        let encrypted = encrypt_uri(path, encrypt_key, context);
        let result = decrypt_uri(&encrypted, decrypt_key, context);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Authentication failed"));
    }

    #[test]
    fn test_invalid_encrypted_format() {
        // Test that encrypted strings without '/' or '://' are rejected
        let invalid_encrypted = "somebase64string";
        let result = decrypt_uri(invalid_encrypted, b"key", b"ctx");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid encrypted URI format"));
    }

    #[test]
    fn test_decrypt_corrupted_component() {
        // Test that if any component fails authentication, the entire decryption fails
        let uri = "https://example.com/path/to/resource";
        let secret_key = b"test_key";
        let context = b"test_context";

        let encrypted = encrypt_uri(uri, secret_key, context);

        // Corrupt the encrypted data by modifying some bytes in the middle
        // This should affect one of the components
        let mut corrupted = encrypted.clone();

        // Find the base64 part after the scheme
        let scheme_end = corrupted.find("://").unwrap() + 3;
        let base64_part = &corrupted[scheme_end..];

        // Decode, corrupt, and re-encode
        let mut decoded = URL_SAFE_NO_PAD.decode(base64_part).unwrap();

        // Corrupt some bytes in the middle (likely affecting a component after the first one)
        if decoded.len() > 50 {
            decoded[45] ^= 0xFF; // Flip bits in a byte that's likely part of a component
            decoded[46] ^= 0xFF;
            decoded[47] ^= 0xFF;
        }

        let corrupted_base64 = URL_SAFE_NO_PAD.encode(&decoded);
        corrupted = format!("https://{}", corrupted_base64);

        // Attempt to decrypt the corrupted URI
        let result = decrypt_uri(&corrupted, secret_key, context);

        // The decryption should fail due to authentication failure
        assert!(
            result.is_err(),
            "Decryption should fail when a component is corrupted"
        );
        assert!(
            result.unwrap_err().contains("Authentication failed"),
            "Error message should indicate authentication failure"
        );
    }

    #[test]
    #[should_panic(expected = "Key validation failed: both halves of the key are identical")]
    fn test_encrypt_with_identical_key_halves_panics() {
        let uri = "https://example.com/path";
        let bad_key = b"same_halfsame_half"; // 18 bytes total, both halves are "same_half"
        let context = b"test";

        // This should panic
        encrypt_uri(uri, bad_key, context);
    }

    #[test]
    fn test_decrypt_with_identical_key_halves_returns_error() {
        let encrypted = "https://fakefakefake"; // Doesn't matter, won't get to decryption
        let bad_key = b"abcd1234abcd1234"; // 16 bytes total, both halves are "abcd1234"
        let context = b"test";

        let result = decrypt_uri(encrypted, bad_key, context);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Key validation failed: both halves of the key are identical"
        );
    }

    #[test]
    fn test_odd_length_key_not_checked_for_identical_halves() {
        let uri = "https://example.com/path";
        let odd_key = b"abcdefghijklmno"; // 15 bytes - odd length, won't be checked
        let context = b"test";

        // Should not panic since odd-length keys aren't checked
        let encrypted = encrypt_uri(uri, odd_key, context);
        assert!(!encrypted.is_empty());

        // Should decrypt successfully
        let decrypted = decrypt_uri(&encrypted, odd_key, context).unwrap();
        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_different_halves_key_works() {
        let uri = "https://example.com/path";
        let good_key = b"first_halfother_half"; // Different halves
        let context = b"test";

        let encrypted = encrypt_uri(uri, good_key, context);
        let decrypted = decrypt_uri(&encrypted, good_key, context).unwrap();
        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_decrypt_tampered_multi_component() {
        // Test with a more controlled corruption - mix components from different encryptions
        let secret_key = b"test_key";
        let context = b"test_context";

        // Encrypt two different URIs - they have different first components
        let uri1 = "https://example.com/path/resource";
        let uri2 = "https://other.com/different/file";

        let encrypted1 = encrypt_uri(uri1, secret_key, context);
        let encrypted2 = encrypt_uri(uri2, secret_key, context);

        // Extract the encrypted parts
        let scheme_end1 = encrypted1.find("://").unwrap() + 3;
        let base64_1 = &encrypted1[scheme_end1..];

        let scheme_end2 = encrypted2.find("://").unwrap() + 3;
        let base64_2 = &encrypted2[scheme_end2..];

        let bytes1 = URL_SAFE_NO_PAD.decode(base64_1).unwrap();
        let bytes2 = URL_SAFE_NO_PAD.decode(base64_2).unwrap();

        // Create a tampered message by mixing components from different encryptions
        // Take first component from encrypted1 and second component from encrypted2
        // This should fail because the SIVs depend on accumulated state
        let mut tampered = Vec::new();

        // Find the boundary between first and second component in encrypted1
        // First component: "example.com/" = 12 bytes, SIV = 16, total = 28, need 2 padding -> 30 bytes
        tampered.extend_from_slice(&bytes1[..30]); // First component from uri1

        // Take second component onwards from encrypted2
        // But this won't work because the second component's SIV in encrypted2
        // was computed with a different first component
        // First component of uri2: "other.com/" = 10 bytes, SIV = 16, total = 26, need 1 padding -> 27 bytes
        if bytes2.len() > 27 {
            tampered.extend_from_slice(&bytes2[27..]); // Second component onwards from uri2
        }

        let tampered_base64 = URL_SAFE_NO_PAD.encode(&tampered);
        let tampered_uri = format!("https://{}", tampered_base64);

        let result = decrypt_uri(&tampered_uri, secret_key, context);

        // Should fail because the second component's SIV won't match
        // (it was calculated with different previous SIVs)
        assert!(
            result.is_err(),
            "Decryption should fail when components are tampered"
        );
        assert!(
            result.unwrap_err().contains("Authentication failed"),
            "Error message should indicate authentication failure"
        );
    }
}
