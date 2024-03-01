use std::fs;

use aes_gcm::{Aes256Gcm, aead::Aead, AeadCore, Key, KeyInit};
use rand_core::{RngCore, OsRng}; // Import the RngCore trait along with OsRng

use base64::prelude::*;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Save bytes to file encoded as Base64.
///
/// The data is encoded using the standard Base64 encoding engine and written to
/// disk.
///
/// # Arguments
///
/// * `file_name` - the path of the file in which the data is to be saved
/// * `data` - the data of to be saved to file
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn save_to_file_as_b64(file_name: &str, data: &[u8]) {
    let base64_data = BASE64_STANDARD.encode(data);
    fs::write(file_name, base64_data).expect("Unable to write to file");
}

/// Read a Base64-encoded file as bytes.
///
/// The data is read from disk and decoded using the standard Base64 encoding
/// engine.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn read_from_b64_file(file_name: &str) -> Vec<u8> {
    let file_contents = fs::read_to_string(file_name).expect("Unable to read from file");
    let decoded_bytes = BASE64_STANDARD
        .decode(file_contents.as_bytes())
        .expect("Unable to decode Base64");
    return decoded_bytes;
}

/// Returns a tuple containing a randomly generated secret key and public key.
///
/// The secret key is a StaticSecret that can be used in a Diffie-Hellman key
/// exchange. The public key is the associated PublicKey for the StaticSecret.
/// The output of this function is a tuple of bytes corresponding to these keys.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn keygen() -> ([u8; 32], [u8; 32]) {
    // Generate a StaticSecret from random
    let secret_key = StaticSecret::random();

    // Generate a PublicKey from the StaticSecret
    let public_key = PublicKey::from(&secret_key);

    // Convert the secret key to bytes
    let secret_key_bytes = secret_key.to_bytes();

    // Convert the public key to bytes
    let public_key_bytes = *public_key.as_bytes();

    // Base64 encode the keys for printing
    let secret_key_b64 = base64::encode(&secret_key_bytes);
    let public_key_b64 = base64::encode(&public_key_bytes);

    // Print the Base64-encoded keys
    println!("Secret Key (Base64): {}", secret_key_b64);
    println!("Public Key (Base64): {}", public_key_b64);

    // Return a tuple of the secret key bytes and public key bytes
    (secret_key_bytes, public_key_bytes)
}

/// Returns the encryption of plaintext data to be sent from a sender to a receiver.
///
/// This function performs a Diffie-Hellman key exchange between the sender's
/// secret key and the receiver's public key. Then, the function uses SHA-256 to
/// derive a symmetric encryption key, which is then used in an AES-256-GCM
/// encryption operation. The output vector contains the ciphertext with the
/// AES-256-GCM nonce (12 bytes long) appended to its end.
///
/// # Arguments
///
/// * `input` - A vector of bytes (`u8`) that represents the plaintext data to be encrypted.
/// * `sender_sk` - An array of bytes representing the secret key of the sender.
/// * `receiver_pk` - An array of bytes representing the public key of the receiver.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn encrypt(input: Vec<u8>, sender_sk: [u8; 32], receiver_pk: [u8; 32]) -> Vec<u8> {
  // Convert the sender's secret key and receiver's public key from bytes
  let sender_secret = StaticSecret::from(sender_sk);
  let receiver_public = PublicKey::from(receiver_pk);

  // Derive a shared secret from the sender's secret key and receiver's public key
  let shared_secret = sender_secret.diffie_hellman(&receiver_public);

  // Hash the shared secret to use as the AES key
  let aes_key = Sha256::digest(shared_secret.as_bytes());

  // Create an AES-GCM instance with the derived key
  let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("Failed to create AES instance");

  // Generate a random nonce for AES-GCM
  let mut nonce = [0u8; 12]; // 96 bits nonce
  OsRng.fill_bytes(&mut nonce);

  // Encrypt the plaintext
  let ciphertext = cipher.encrypt(&nonce.into(), input.as_ref())
      .expect("encryption failure!");

  // Concatenate nonce and ciphertext for the output
  [nonce.to_vec(), ciphertext].concat()
}


/// Returns the decryption of ciphertext data to be received by a receiver from a sender.
///
/// This function performs a Diffie-Hellman key exchange between the receiver's
/// secret key and the sender's public key. Then, the function uses SHA-256 to
/// derive a symmetric encryption key, which is then used in an AES-256-GCM
/// decryption operation. The nonce for this decryption is the last 12 bytes of
/// the input. The output vector contains the plaintext.
///
/// # Arguments
///
/// * `input` - A vector of bytes that represents the ciphertext data to be encrypted and the associated nonce.
/// * `receiver_sk` - An array of bytes representing the secret key of the receiver.
/// * `sender_pk` - An array of bytes representing the public key of the sender.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn decrypt(input: Vec<u8>, receiver_sk: [u8; 32], sender_pk: [u8; 32]) -> Vec<u8> {
    // TODO
    unimplemented!()
}

/// The main function, which parses arguments and calls the correct cryptographic operations.
///
/// # Note
///
/// **Do not modify this function**.
///
fn main() {
    // Collect command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Command parsing: keygen, encrypt, decrypt
    let cmd = &args[1];
    if cmd == "keygen" {
        // Arguments to the command
        let secret_key = &args[2];
        let public_key = &args[3];

        // Generate a secret and public key for this user
        let (sk_bytes, pk_bytes) = keygen();

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&secret_key, &sk_bytes);
        save_to_file_as_b64(&public_key, &pk_bytes);
    } else if cmd == "encrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let sender_sk = &args[4];
        let receiver_pk = &args[5];

        // Read input from file
        // Note that this input is not necessarily Base64-encoded
        let input = fs::read(input).unwrap();

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let sender_sk: [u8; 32] = read_from_b64_file(sender_sk).try_into().unwrap();
        let receiver_pk: [u8; 32] = read_from_b64_file(receiver_pk).try_into().unwrap();

        // Call the encryption operation
        let output_bytes = encrypt(input, sender_sk, receiver_pk);

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&output, &output_bytes);
    } else if cmd == "decrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let receiver_sk = &args[4];
        let sender_pk = &args[5];

        // Read the Base64-encoded input ciphertext from file
        let input = read_from_b64_file(&input);

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let receiver_sk: [u8; 32] = read_from_b64_file(&receiver_sk).try_into().unwrap();
        let sender_pk: [u8; 32] = read_from_b64_file(&sender_pk).try_into().unwrap();

        // Call the decryption operation
        let output_bytes = decrypt(input, receiver_sk, sender_pk);

        // Save those bytes as Base64 to file
        fs::write(output, output_bytes).unwrap();
    } else {
        panic!("command not found!")
    }
}

#[cfg(test)]
mod tests {
    // TODO: Write tests that validate your encryption and decryption functionality
    // Use the values in README.md to write these tests
    // You may have to split up function to write tests
    // For example, how can you test that both parties reach the same AES key?
}
