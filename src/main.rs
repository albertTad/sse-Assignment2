use std::fs;

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit,
};

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
    // Encode data as Base64 using the engine BASE64_STANDARD.
    let base64_data: String = BASE64_STANDARD.encode(data);

    // Write the contents of the Base64 string to the file given by file_name.
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
    // Read the contents of the file given by file_name.
    let file_contents: String = fs::read_to_string(file_name).expect("Unable to read from file");

    // Decode the contents of the file using the engine BASE64_STANDARD.
    let decoded_bytes: Vec<u8> = BASE64_STANDARD
        .decode(file_contents.as_bytes())
        .expect("Unable to decode Base64");

    // Return the decoded bytes.
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
    // Generate a StaticSecret from random.
    let secret_key: StaticSecret = StaticSecret::random();

    // Generate a PublicKey from this StaticSecret.
    let public_key: PublicKey = PublicKey::from(&secret_key);

    // Convert the secret and public keys to bytes.
    let secret_key_bytes: [u8; 32] = secret_key.to_bytes();
    let public_key_bytes: [u8; 32] = *public_key.as_bytes();

    // Return a tuple of the secret key bytes and public key bytes.
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
    // Convert the sender secret key array into a StaticSecret.
    let sender_secret_key = StaticSecret::from(sender_sk);

    // Convert the receiver public key array into a PublicKey.
    let receiver_public_key = PublicKey::from(receiver_pk);

    // Perform Diffie-Hellman key exchange to generate a SharedSecret.
    let shared_secret = sender_secret_key.diffie_hellman(&receiver_public_key);

    // Hash the SharedSecret into 32 bytes using SHA-256.
    let hashed_shared_secret = Sha256::digest(&shared_secret.as_bytes());

    // hasher.update(shared_secret);
    // let hashed_shared_secret = hasher.finalize();

    // let hashed_shared_secret = Sha256::new(&shared_secret);
    // hasher.update(shared_secret);
    // let hashed_shared_secret = hasher.finalize();

    // Transform the hashed bytes into an AES-256-GCM key (Key<Aes256Gcm>).
    let aes_key = Key::<Aes256Gcm>::from_slice(&hashed_shared_secret);

    // Generate a random nonce for AES-256-GCM.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the input under the AES-256-GCM key and nonce.
    let cipher = Aes256Gcm::new(&aes_key);

    let ciphertext = cipher
        .encrypt(&nonce, input.as_ref())
        .expect("encryption failure!");

    // Return the vector of bytes containing the ciphertext and the nonce.
    // Directly concatenate the bytes of the nonce with the ciphertext
    // Used concat() before but that may not correctly append the nonce to the ciphertext

    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&ciphertext);
    encrypted_data.extend_from_slice(&nonce);

    return encrypted_data;
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
    // Convert the receiver secret key array into a StaticSecret
    let receiver_sk = StaticSecret::from(receiver_sk);

    // Convert the sender public key array into a PublicKey
    let sender_pk = PublicKey::from(sender_pk);

    // Perform Diffie-Hellman key exchange to generate a SharedSecret
    let shared_secret = receiver_sk.diffie_hellman(&sender_pk);

    // Hash the SharedSecret into 32 bytes using SHA-256
    let hashed_shared_secret = Sha256::digest(&shared_secret.as_bytes());

    // Transform the hashed bytes into an AES-256-GCM key (Key<Aes256Gcm>)
    let aes_key = Key::<Aes256Gcm>::from_slice(&hashed_shared_secret);

    // Extract the ciphertext and the nonce from input.
    let (ciphertext, nonce) = input.split_at(input.len() - 12);

    // Convert the nonce into a fixed-size array
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);

    let cipher = Aes256Gcm::new(aes_key);

    // Decrypt the ciphertext using the AES-256-GCM key and nonce.
    let decrypted = cipher
        .decrypt(&nonce_arr.into(), ciphertext)
        .expect("decryption failure!");

    // Return the vector of bytes containing the plaintext data.
    return decrypted;
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
    use super::*;

    #[test]
    fn test_key_exchange() {
        // Generate sender and receiver keys
        let (sender_sk_bytes, sender_pk_bytes) = keygen();
        let (receiver_sk_bytes, receiver_pk_bytes) = keygen();

        // Convert byte arrays to StaticSecret instances
        let sender_sk = StaticSecret::from(sender_sk_bytes);
        let receiver_sk = StaticSecret::from(receiver_sk_bytes);

        // Convert public key byte arrays to PublicKey instances
        let sender_pk = PublicKey::from(sender_pk_bytes);
        let receiver_pk = PublicKey::from(receiver_pk_bytes);

        // Perform key exchange
        let sender_shared_secret = sender_sk.diffie_hellman(&receiver_pk);
        let receiver_shared_secret = receiver_sk.diffie_hellman(&sender_pk);

        // Since binary operation `==` cannot be applied to type `SharedSecret`
        // Convert shared secrets to byte arrays
        let sender_shared_secret_bytes = sender_shared_secret.as_bytes();
        let receiver_shared_secret_bytes = receiver_shared_secret.as_bytes();

        // Ensure both parties derive the same shared secret
        assert_eq!(
            sender_shared_secret_bytes, receiver_shared_secret_bytes,
            "Shared secrets are not equal"
        );
    }

    // a unit test for encryption and decryption
    #[test]
    fn test_encrypt_decrypt() {
        // Example keys (normally generated via keygen(), but hardcoded here for testing)
        let sender_sk_bytes: [u8; 32] = [
            77, 105, 123, 62, 170, 198, 29, 150, 82, 70, 152, 150, 38, 114, 94, 160, 7, 84, 131,
            221, 130, 89, 77, 243, 191, 147, 174, 121, 49, 91, 187, 214,
        ];
        let receiver_pk_bytes: [u8; 32] = [
            246, 88, 196, 62, 121, 69, 20, 123, 199, 128, 26, 114, 238, 35, 255, 153, 209, 43, 110,
            231, 78, 227, 115, 192, 90, 20, 40, 5, 151, 98, 253, 123,
        ];

        // Example plaintext
        let plaintext = b"Hello, world!";

        // Encrypt the plaintext
        let encrypted_data = encrypt(plaintext.to_vec(), sender_sk_bytes, receiver_pk_bytes);

        // Assuming the receiver's secret key and sender's public key are known
        // Here we use predefined keys for testing
        let receiver_sk_bytes = sender_sk_bytes;
        let sender_pk_bytes = receiver_pk_bytes;

        // Decrypt the encrypted data
        let decrypted_data = decrypt(encrypted_data, receiver_sk_bytes, sender_pk_bytes);

        // Verify that the decrypted data matches the original plaintext
        assert_eq!(
            plaintext,
            &decrypted_data[..],
            "Decrypted data does not match the original plaintext."
        );
    }
}
