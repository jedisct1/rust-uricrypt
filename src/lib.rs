use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    TurboShake128, TurboShake128Core,
};

/// Splits a URI into its scheme and hierarchical components.
/// Returns (scheme_with_separator, components) where scheme includes "://" if present.
/// For path-only URIs (no scheme), returns (None, components).
pub(crate) fn split_uri(uri: &str) -> (Option<&str>, Vec<&str>) {
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
pub(crate) fn xor_in_place(data: &mut [u8], keystream: &[u8]) {
    for (d, k) in data.iter_mut().zip(keystream.iter()) {
        *d ^= k;
    }
}

/// Size of the Synthetic Initialization Vector (SIV) in bytes.
/// Used for authentication tags on each URI component.
pub(crate) const SIV_SIZE: usize = 16;

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
mod tests;
