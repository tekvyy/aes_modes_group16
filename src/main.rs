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
use aes::{
	cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
	Aes128,
};
use rand::{thread_rng, Rng};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
	let key = [0u8; BLOCK_SIZE];
    let plain_text = b"Hello, world! This is a test message.".to_vec();

    let encrypted = cbc_encrypt(plain_text.clone(), key);
    println!("Encrypted: {:?}", encrypted);

    let decrypted = cbc_decrypt(encrypted, key);
    println!("Decrypted: {:?}", String::from_utf8(decrypted).unwrap());

	let ctr_encrypted = ctr_encrypt(plain_text.clone(), key);
	println!("Encrypted: {:?}", ctr_encrypted);

	let ctr_decrypted = ctr_decrypt(ctr_encrypted, key);
	println!("Decrypted: {:?}", ctr_decrypted.iter().map(|c| *c as char).collect::<String>());

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
	todo!()
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
	// todo!()
	if let Some(&last_byte) = data.last() {
        let pad_size = last_byte as usize;
        if pad_size <= BLOCK_SIZE {
            return data[..data.len() - pad_size].to_vec();
        }
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
	todo!()
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	todo!()
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
		let plain_text = pad(plain_text);
		let blocks = group(plain_text);
	
		let iv: [u8; BLOCK_SIZE] = rand::thread_rng().gen();
		let mut prev_block = iv;
	
		let mut cipher_text = Vec::from(iv);
	
		for block in blocks {
			let mut xor_block = [0u8; BLOCK_SIZE];
			for (i, &byte) in block.iter().enumerate() {
				xor_block[i] = byte ^ prev_block[i];
			}
			let encrypted_block = aes_encrypt(xor_block, &key);
			cipher_text.extend_from_slice(&encrypted_block);
			prev_block = encrypted_block;
		}
	
		cipher_text
		// todo!()
	}
	



	
	fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
		let iv: [u8; BLOCK_SIZE] = cipher_text[..BLOCK_SIZE].try_into().unwrap();
		let cipher_blocks = group(cipher_text[BLOCK_SIZE..].to_vec());
	
		let mut plain_text = Vec::new();
		let mut prev_block = iv;
	
		for block in cipher_blocks {
			let decrypted_block = aes_decrypt(block, &key);
			let mut xor_block = [0u8; BLOCK_SIZE];
			for (i, &byte) in decrypted_block.iter().enumerate() {
				xor_block[i] = byte ^ prev_block[i];
			}
			plain_text.extend_from_slice(&xor_block);
			prev_block = block;
		}
	
		un_pad(plain_text)
		// todo!()
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
	let plain_text = pad(plain_text);
	let mut cipher_text: Vec<u8> = Vec::new();
	let mut nonce = [0u8; BLOCK_SIZE /2 ];
	thread_rng().fill(&mut nonce[..BLOCK_SIZE /2]);

	cipher_text.extend_from_slice(&nonce); 

	let blocks = group(plain_text);
	let mut counter = 1; 

	for block in blocks.iter() {
		
		let mut ctr_block = nonce.to_vec();

		ctr_block.extend_from_slice(&(counter as u64).to_le_bytes()[..BLOCK_SIZE/2]);
		let ctr_block_array: [u8; BLOCK_SIZE] = ctr_block.try_into().unwrap();

		let encrypted_ctr = aes_encrypt(ctr_block_array, &key);

		let mut xor_block: Vec<u8> = Vec::with_capacity(block.len());
		for (a, b) in block.iter().zip(encrypted_ctr.iter()) {
			xor_block.push(a ^ b);
		}

		cipher_text.extend_from_slice(&xor_block);
		counter += 1;
	}

	cipher_text
}
	
fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {

	let mut plain_text: Vec<u8> = Vec::new();
	let nonce = cipher_text[..BLOCK_SIZE /2].to_vec(); 

	// let blocks: Vec<u8> = cipher_text[BLOCK_SIZE..].chunks(BLOCK_SIZE).map(|b| b.try_into().unwrap()).collect();

	let mut blocks: Vec<[u8; 16]> = Vec::new();
	let mut remaining = &cipher_text[BLOCK_SIZE..];
	while remaining.len() >= BLOCK_SIZE {
		let block = remaining[..BLOCK_SIZE].try_into().unwrap();
		blocks.push(block);
		remaining = &remaining[BLOCK_SIZE..];
	}
	let mut counter = 1;

	for block in blocks.iter() {

		let mut ctr_block = nonce.to_vec();
		ctr_block.extend_from_slice(&(counter as u64).to_le_bytes()[..BLOCK_SIZE / 2]);

		let ctr_block_array: [u8; BLOCK_SIZE] = ctr_block.try_into().unwrap();
		let encrypted_ctr = aes_encrypt(ctr_block_array, &key);
		let mut xor_block: Vec<u8> = Vec::with_capacity(block.len());
		for (a, b) in block.iter().zip(encrypted_ctr.iter()) {
			xor_block.push(a ^ b);
		}

		plain_text.extend_from_slice(&xor_block);
		counter += 1;
	}

	un_pad(plain_text)
}