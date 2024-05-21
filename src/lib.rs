//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use std::{result, usize};

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();

    for block in blocks {
        data.extend_from_slice(&block);
    }

    data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
    let mut data = data;
    let last_byte = *data.last().unwrap() as usize;

    match last_byte == BLOCK_SIZE {
        true => data.truncate(data.len() - BLOCK_SIZE),
        false => data.truncate(data.len() - last_byte),
    }

    data
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let padded = pad(plain_text.clone());
    let grouped_blocks = group(padded);

    let mut ciphered_data = Vec::new();

    for block in grouped_blocks {
        ciphered_data.extend_from_slice(&aes_encrypt(block, &key));
    }

    ciphered_data
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let grouped_cipher = group(cipher_text);

    let mut decrypted_text = Vec::new();

    for block in grouped_cipher {
        decrypted_text.extend_from_slice(&aes_decrypt(block, &key));
    }

    un_pad(decrypted_text)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut result: Vec<[u8; BLOCK_SIZE]> = vec![];
    // Remember to generate a random initialization vector for the first block.
    // 1. generate init vector -> BLOCK_SIZE bytes
    let iv = [1u8; BLOCK_SIZE];
    result.push(iv);

    let groups = group(pad(plain_text));

    for block in groups {
        let xored = xor(&result.last().unwrap(), &block);
        let encrytped = aes_encrypt(xored, &key);

        result.push(encrytped);
    }

    un_group(result)
}

fn xor(v1: &[u8; BLOCK_SIZE], v2: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let vec: Vec<u8> = v1.iter().zip(v2.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();

    vec.try_into().unwrap()
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let blocks = group(cipher_text);
    let mut iv = blocks.first().unwrap().clone();
    let mut result = vec![];
    for i in 1..blocks.len() {
        let block = blocks.get(i).unwrap();

        let decrypted = aes_decrypt(*block, &key);

        let xored = xor(&iv, &decrypted);

        result.push(xored);

        iv = *block;
    }
    let decrypted = un_group(result);

    un_pad(decrypted)
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    todo!()
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_encryption() {
        let data = vec![1, 2, 3];
        let key = [5u8; BLOCK_SIZE];
        let cipher = cbc_encrypt(data.clone(), key.clone());

        let plain_text = cbc_decrypt(cipher, key.clone());

        assert_eq!(plain_text, data);
    }

    #[test]
    fn test_cbc_encryption_02() {
        let data: Vec<u8> = [8u8; BLOCK_SIZE].try_into().unwrap();
        let key = [5u8; BLOCK_SIZE];
        let cipher = cbc_encrypt(data.clone(), key.clone());

        let plain_text = cbc_decrypt(cipher, key.clone());

        assert_eq!(plain_text, data);
    }

    #[test]
    fn test_cbc_encryption_03() {
        let data: Vec<u8> = [8u8; BLOCK_SIZE + 6].try_into().unwrap();
        let key = [5u8; BLOCK_SIZE];
        let cipher = cbc_encrypt(data.clone(), key.clone());

        let plain_text = cbc_decrypt(cipher, key.clone());

        assert_eq!(plain_text, data);
    }

    #[test]
    fn test_ecb_encrypt() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let key = [5u8; BLOCK_SIZE];
        let cipher = ecb_encrypt(data.clone(), key.clone());

        let plain_text = ecb_decrypt(cipher, key.clone());

        assert_eq!(plain_text, data);
    }

    #[test]
    fn test_ecb_encrypt_with_16_block_size() {
        let data: Vec<u8> = [8u8; BLOCK_SIZE].try_into().unwrap();
        let key = [5u8; BLOCK_SIZE];
        let cipher = ecb_encrypt(data.clone(), key.clone());

        let plain_text = ecb_decrypt(cipher, key.clone());

        assert_eq!(plain_text, data);
    }
}
