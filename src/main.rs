use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use cbc::{Decryptor, Encryptor};
use image::Luma;
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sm4::Sm4;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Type Definitions for SM4 CBC Mode ---
// SM4 block size is 16 bytes. We use CBC mode with PKCS7 padding.
type Sm4CbcEnc = Encryptor<Sm4>;
type Sm4CbcDec = Decryptor<Sm4>;

#[derive(Serialize, Deserialize, Debug)]
struct QrPayload {
    uid: String,
    ts: u64,
    nonce: String,
}

fn main() {
    // 1. Configuration (In production, load KEY from a secure environment variable/vault)
    // Key must be 16 bytes (128 bits)
    let key_bytes = b"0123456789ABCDEF"; 

    // 2. Create the dynamic data
    let user_id = "user_8888";
    let payload = create_payload(user_id);
    println!("Plaintext Payload: {}", serde_json::to_string(&payload).unwrap());

    // 3. Encrypt the data (SM4-CBC)
    // Returns Base64 string containing [IV + EncryptedData]
    let qr_content = match encrypt_sm4_dynamic(key_bytes, &payload) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Encryption error: {}", e);
            return;
        }
    };
    println!("Generated QR Content (Base64): {}", qr_content);

    // 4. Generate QR Code Image
    generate_qr_image(&qr_content, "dynamic_sm4_qr.png");

    // 5. Verify/Validate (Optional - for demonstration/testing)
    println!("\n--- Validation ---");
    match decrypt_sm4_dynamic(key_bytes, &qr_content) {
        Ok(decrypted_payload) => {
            println!("Decryption Successful!");
            println!("Refined Payload: {:?}", decrypted_payload);
            
            // Verify if it matches
            if decrypted_payload.uid == user_id && decrypted_payload.nonce == payload.nonce {
                 println!(">> Verification values match!");
            } else {
                 eprintln!(">> Verification Content Mismatch!");
            }
        },
        Err(e) => eprintln!("Decryption failed: {}", e),
    }
}

/// Creates the payload with current timestamp and random nonce
fn create_payload(uid: &str) -> QrPayload {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    // Generate a random 6-character nonce string
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    QrPayload {
        uid: uid.to_string(),
        ts: since_the_epoch.as_secs(),
        nonce,
    }
}

/// Encrypts the payload using SM4-CBC with a random IV
fn encrypt_sm4_dynamic(key: &[u8; 16], payload: &QrPayload) -> Result<String, Box<dyn std::error::Error>> {
    // A. Serialize payload to JSON
    let json_data = serde_json::to_string(payload)?;
    let plaintext_bytes = json_data.as_bytes();

    // B. Generate a Random IV (Initialization Vector) - 16 bytes
    // Using a random IV is critical so that identical payloads (e.g. same second)
    // produce different ciphertexts.
    let mut iv = [0u8; 16];
    rand::thread_rng().fill(&mut iv);

    // C. Initialize Encryptor
    let encryptor = Sm4CbcEnc::new(key.into(), &iv.into());

    // D. Encrypt with PKCS7 Padding
    // Calculate buffer size needed for padding
    let pt_len = plaintext_bytes.len();
    let block_size = 16;
    let padded_len = pt_len + (block_size - (pt_len % block_size));
    let mut buffer = vec![0u8; padded_len];
    
    // Copy plaintext into buffer
    buffer[..pt_len].copy_from_slice(plaintext_bytes);

    // Perform encryption using the buffer
    // Note: encrypt_padded_b2b_mut is convenient if we have input/output slices,
    // but here we use the buffer approach with `encrypt_padded_mut`.
    let ciphertext = encryptor.encrypt_padded_mut::<Pkcs7>(&mut buffer, pt_len)
        .map_err(|e| format!("Padding error: {:?}", e))?;

    // E. Combine IV + Ciphertext
    // The decryptor needs the IV. Usually, it's prepended to the ciphertext.
    let mut final_data = Vec::with_capacity(iv.len() + ciphertext.len());
    final_data.extend_from_slice(&iv); // Prepend IV
    final_data.extend_from_slice(ciphertext); // Append Encrypted Data

    // F. Base64 Encode
    let encoded_str = general_purpose::STANDARD.encode(&final_data);
    Ok(encoded_str)

}

/// Decrypts the Base64 encoded string back to QrPayload
fn decrypt_sm4_dynamic(key: &[u8; 16], encrypted_str: &str) -> Result<QrPayload, Box<dyn std::error::Error>> {
    // A. Decode Base64
    let encrypted_data = general_purpose::STANDARD.decode(encrypted_str)?;

    if encrypted_data.len() < 16 {
        return Err("Data too short to contain IV".into());
    }

    // B. Extract IV and Ciphertext
    let (iv, ciphertext) = encrypted_data.split_at(16);
    let iv_array: [u8; 16] = iv.try_into().expect("IV size incorrect");
    
    // C. Initialize Decryptor
    let decryptor = Sm4CbcDec::new(key.into(), &iv_array.into());

    // D. Decrypt with PKCS7 Padding
    // We need to copy ciphertext to a mutable buffer for in-place decryption or use a separate buffer.
    // Since `decrypt_padded_mut` works in-place (or on a buffer), let's create a buffer.
    let mut buffer = ciphertext.to_vec();
    
    // The `decrypt_padded_mut` method returns a slice of the plaintext (without padding).
    let plaintext = decryptor.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| format!("Decryption padding error: {:?}", e))?;

    // E. Deserialize JSON
    let plaintext_str = std::str::from_utf8(plaintext)?;
    let payload: QrPayload = serde_json::from_str(plaintext_str)?;

    Ok(payload)
}

/// Generates a PNG file from the string content
fn generate_qr_image(content: &str, filepath: &str) {
    // Generate QR code
    let code = QrCode::new(content).unwrap();

    // Render to Image
    let image = code.render::<Luma<u8>>().build();

    // Save
    image.save(filepath).unwrap();
    println!(">> QR Code saved to: {}", filepath);
}