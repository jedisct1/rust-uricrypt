use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    TurboShake128, TurboShake128Core,
};

/// Represents URI components that can be iterated without allocation.
pub(crate) struct URIComponents<'a> {
    uri: &'a str,
    scheme: Option<&'a str>,
    /// Start position for component extraction (after scheme if present)
    rest_start: usize,
}

impl<'a> URIComponents<'a> {
    /// Returns the scheme portion of the URI, if present.
    pub fn scheme(&self) -> Option<&'a str> {
        self.scheme
    }
}

impl<'a> IntoIterator for URIComponents<'a> {
    type Item = &'a str;
    type IntoIter = URIComponentIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        let rest = &self.uri[self.rest_start..];

        // Handle empty rest
        if rest.is_empty() {
            return URIComponentIterator {
                rest: "",
                position: 0,
                done: true,
            };
        }

        // For path-only URIs (no scheme), use the entire URI
        if self.scheme.is_none() {
            return URIComponentIterator {
                rest: self.uri,
                position: 0,
                done: false,
            };
        }

        // URI with scheme - iterate over rest
        URIComponentIterator {
            rest,
            position: 0,
            done: false,
        }
    }
}

/// Iterator over URI components without allocation.
pub(crate) struct URIComponentIterator<'a> {
    rest: &'a str,
    position: usize,
    done: bool,
}

impl<'a> Iterator for URIComponentIterator<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.position >= self.rest.len() {
            self.done = true;
            return None;
        }

        // Find next component ending with '/', '?', or '#'
        let remaining = &self.rest[self.position..];
        let mut end_pos = None;
        let mut include_terminator = false;

        // Find the nearest terminator ('/', '?', or '#')
        for (i, ch) in remaining.chars().enumerate() {
            if ch == '/' || ch == '?' || ch == '#' {
                end_pos = Some(i);
                include_terminator = true;
                break;
            }
        }

        if let Some(pos) = end_pos {
            let end = self.position + pos + if include_terminator { 1 } else { 0 };
            let component = &self.rest[self.position..end];
            self.position = end;
            return Some(component);
        }

        // Last component (no trailing slash)
        if self.position < self.rest.len() {
            let component = &self.rest[self.position..];
            self.done = true;
            return Some(component);
        }

        self.done = true;
        None
    }
}

/// Splits a URI into its scheme and hierarchical components.
/// Returns a structure that provides the scheme (if present) and allows
/// iteration over components without allocation.
pub(crate) fn split_uri(uri: &str) -> URIComponents<'_> {
    if let Some(scheme_end) = uri.find("://") {
        let scheme = &uri[..scheme_end + 3];
        return URIComponents {
            uri,
            scheme: Some(scheme),
            rest_start: scheme_end + 3,
        };
    }

    URIComponents {
        uri,
        scheme: None,
        rest_start: 0,
    }
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
/// For path-only URIs (no scheme), returns just the base64-encoded ciphertext
/// without any prefix.
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
/// For path-only URIs, returns just the base64-encoded ciphertext.
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
    let components = split_uri(uri);
    let scheme = components.scheme();

    let mut encrypted_uri = Vec::with_capacity(uri.len() * 2);

    let mut base_hasher = TurboShake128::from_core(TurboShake128Core::new(0x1F));
    base_hasher.update(&[secret_key.len() as u8]);
    base_hasher.update(secret_key);
    base_hasher.update(&[context.len() as u8]);
    base_hasher.update(context);

    let mut components_hasher = base_hasher.clone();
    components_hasher.update(b"IV");
    let mut base_keystream_hasher = base_hasher.clone();
    base_keystream_hasher.update(b"KS");

    for part in components {
        let part_bytes = part.as_bytes();

        let total_unpadded = SIV_SIZE + part_bytes.len();
        let padding = (3 - (total_unpadded % 3)) % 3;

        components_hasher.update(part_bytes);

        let mut siv = [0u8; SIV_SIZE];
        components_hasher.clone().finalize_xof().read(&mut siv);

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

    match scheme {
        Some(s) => format!("{}{}", s, URL_SAFE_NO_PAD.encode(encrypted_uri)),
        None => URL_SAFE_NO_PAD.encode(encrypted_uri)
    }
}

/// Decrypts a URI that was encrypted with `encrypt_uri`.
///
/// Expects either:
/// - A URI with a plaintext scheme followed by base64-encoded encrypted components
/// - A base64-encoded string (for path-only URIs with no scheme)
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
/// Returns `Err("Decryption failed")` for ALL failure cases to prevent
/// timing and padding oracle attacks. This includes:
/// - Invalid base64 encoding
/// - Malformed encrypted data
/// - Authentication failures (wrong key/context)
/// - Invalid format
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
    let (scheme, encrypted_part) = if let Some(scheme_end) = encrypted_uri.find("://") {
        let scheme = &encrypted_uri[..scheme_end + 3];
        let encrypted = &encrypted_uri[scheme_end + 3..];

        if encrypted.is_empty() {
            return Ok(scheme.to_string());
        }

        (Some(scheme), encrypted)
    } else {
        // No scheme found, treat entire string as encrypted path
        (None, encrypted_uri)
    };

    let encrypted_bytes = URL_SAFE_NO_PAD
        .decode(encrypted_part)
        .map_err(|_| "Decryption failed".to_string())?;

    let mut decrypted_components = Vec::<String>::new();
    let mut pos = 0;

    let mut base_hasher = TurboShake128::from_core(TurboShake128Core::new(0x1F));
    base_hasher.update(&[secret_key.len() as u8]);
    base_hasher.update(secret_key);
    base_hasher.update(&[context.len() as u8]);
    base_hasher.update(context);

    let mut components_hasher = base_hasher.clone();
    components_hasher.update(b"IV");

    let mut base_keystream_hasher = base_hasher.clone();
    base_keystream_hasher.update(b"KS");

    while pos < encrypted_bytes.len() {
        if pos + SIV_SIZE > encrypted_bytes.len() {
            return Err("Decryption failed".to_string());
        }

        let siv = &encrypted_bytes[pos..pos + SIV_SIZE];
        let component_start = pos + SIV_SIZE;
        pos += SIV_SIZE;

        let mut keystream_hasher = base_keystream_hasher.clone();
        keystream_hasher.update(siv);
        let mut reader = keystream_hasher.finalize_xof();

        let mut component = Vec::with_capacity(64);

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

            // Check if this byte is a terminator ('/', '?', or '#')
            if decrypted_byte == b'/' || decrypted_byte == b'?' || decrypted_byte == b'#' {
                let bytes_read = pos - component_start;
                let total_len = SIV_SIZE + bytes_read;
                let padding_needed = (3 - (total_len % 3)) % 3;
                pos += padding_needed;
                break;
            }
        }

        if component.is_empty() {
            return Err("Decryption failed".to_string());
        }

        components_hasher.update(&component);

        let mut expected_siv = [0u8; SIV_SIZE];
        components_hasher
            .clone()
            .finalize_xof()
            .read(&mut expected_siv);

        if expected_siv != siv {
            return Err("Decryption failed".to_string());
        }

        match std::str::from_utf8(&component) {
            Ok(comp_str) => {
                decrypted_components.push(comp_str.to_string());
            }
            Err(_) => return Err("Decryption failed".to_string()),
        }
    }

    if decrypted_components.is_empty() {
        return Err("Decryption failed".to_string());
    }

    // Join all decrypted components
    let decrypted_uri = decrypted_components.join("");

    // Prepend scheme if present
    Ok(match scheme {
        Some(s) => format!("{}{}", s, decrypted_uri),
        None => decrypted_uri,
    })
}

#[cfg(test)]
mod tests;
