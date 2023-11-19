use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hex_literal::hex;
use std::{env, io};
use std::str;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn userinput(text: &str) {
    let mut input = String::new();
    println!("{}", text);
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
}

fn main() {
    let iv = hex!("0xigjghfxcgvhbjngfjhfghj");

    let mut message = String::from("Rust Crypto");
    let mut mykey = String::from("2b7e151628aed2a6abf7158809cf4f3c");

    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        message = args[1].clone();
    }

    if args.len() > 2 {
        mykey = args[2].clone();
    }

    println!("Message: {}", message);
    println!("Key: {}", mykey);
    println!("IV: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    let plaintext: &[u8] = message.as_bytes();
    let key: Vec<u8> = hex::decode(mykey).expect("Decoding failed");

    let cipher: Cbc<Aes128, Pkcs7> = Aes128Cbc::new_from_slices(&key, &iv).unwrap();

    let pos: usize = plaintext.len();

    let mut buffer: [u8; 128] = [0u8; 128];

    buffer[..pos].copy_from_slice(plaintext);

    let ciphertext: &[u8] = cipher.encrypt(&mut buffer, pos).unwrap();

    println!("\nCiphertext: {:?}", hex::encode(ciphertext));

    let cipher: Cbc<Aes128, Pkcs7> = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    let mut buf: Vec<u8> = ciphertext.to_vec();
    let decrypted_ciphertext: &[u8] = cipher.decrypt(&mut buf).unwrap();

    println!(
        "\nCiphertext: {:?}",
        str::from_utf8(decrypted_ciphertext).unwrap()
    );
}
