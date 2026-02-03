# SM4 Dynamic QR Code Generator

A Rust-based utility for generating dynamic QR codes encrypted with the **SM4** (Chinese national standard) block cipher. This project demonstrates how to create a secure, time-sensitive QR code payload suitable for access control, payments, or authentication.

## Features

- **SM4-CBC Encryption**: Uses the SM4 block cipher in Cipher Block Chaining (CBC) mode with PKCS7 padding for secure data encryption.
- **Dynamic Payload**: Generates a JSON payload containing:
  - `uid`: User identifier.
  - `ts`: Unix timestamp (to prevent replay attacks).
  - `nonce`: A random 6-character alphanumeric string for uniqueness.
- **Random IV**: Each encryption uses a fresh, random Initialization Vector (IV).
- **Base64 Encoding**: The final QR content is a Base64-encoded string combining the IV and the encrypted payload.
- **QR Code Generation**: Automatically generates a PNG image of the QR code.
- **Verification Logic**: Includes built-in decryption and validation logic to ensure data integrity.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- `cargo` (included with Rust)

## Dependencies

The project relies on several key Rust crates:
- `sm4`: Implementation of the SM4 block cipher.
- `cbc`: CBC mode of operation.
- `qrcode`: For QR code generation logic.
- `image`: To save the QR code as a PNG file.
- `serde` & `serde_json`: For JSON serialization/deserialization.
- `rand`: For generating random IVs and nonces.

## Usage

To run the demonstration and generate a sample QR code:

```bash
cargo run
```

This will:
1. Create a dynamic payload for a sample user.
2. Encrypt the payload using SM4-CBC with a hardcoded test key (`0123456789ABCDEF`).
3. Save the resulting QR code as `dynamic_sm4_qr.png` in the project root.
4. Perform a validation step by decrypting the generated content and comparing it with the original data.

## Configuration

> [!IMPORTANT]
> For production use, never hardcode the encryption key. The 128-bit (16-byte) key should be loaded from a secure environment variable or a secrets management vault.

## License

This project is licensed under the MIT License.
