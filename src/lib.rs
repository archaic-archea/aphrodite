#![feature(fs_try_exists)]
#![feature(file_create_new)]

use std::{fs, io::Write, os::unix::prelude::FileExt};

pub struct BlockFile {
    path: &'static str,
    blocks: usize
}

impl BlockFile {
    pub fn new(path: &'static str) -> BlockFile {
        let blck = BlockFile { path, blocks: 0};

        if !fs::try_exists(path).expect("Failed") {
            fs::File::create_new(path).unwrap();
        }

        blck
    }

    pub fn append(&mut self, data: &Block) {
        let mut open_options = fs::OpenOptions::new();
        let mut file = open_options.append(true).open(self.path).expect("Failed to grab block file");

        file.write(&data.to_bytes()).expect("Failed to write to block file");

        self.blocks += 1;
    }

    pub fn read(&self, index: usize) -> Block {
        assert!(index < self.blocks, "Index too high for block chain");

        let mut open_options = fs::OpenOptions::new();
        let file = open_options.read(true).open(self.path).expect("Failed to grab block file");

        let mut data = [0; 544];

        file.read_exact_at(&mut data, (index as u64) * 544).expect("Failed to read at offset");

        Block::from_bytes(data)
    }

    pub fn append_enc(&mut self, data: &Block, public_key: rsa::RsaPublicKey) {
        use rsa::PublicKey;

        let mut rng = rand::thread_rng();

        let mut enc_email = Block::null();
        enc_email.to(data.to);
        enc_email.from(data.from);

        let mut message = Vec::new();

        let mut index = 0;
        while data.message[index] != 0 {
            message.push(data.message[index]);
            index += 1;

            if index >= 512 {
                break;
            }
        }

        let enc_data = public_key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &message[..]).expect("Failed to encrypt");

        enc_email.message_vec(&enc_data);

        self.append(&enc_email);
    }

    pub fn read_enc(&self, private_key: rsa::RsaPrivateKey, index: usize) -> Vec<u8> {
        let mut enc_email = self.read(index).message.to_vec();

        for i in (0..enc_email.len()).rev() {
            if enc_email[i] == 0 {
                enc_email.remove(i);
            } else {
                break;
            }
        }

        let enc_data = private_key.decrypt(rsa::Pkcs1v15Encrypt, &enc_email[..]).expect("failed to decrypt");

        enc_data
    }
}

pub struct Block {
    to: Addr,
    from: Addr,
    message: [u8; 512]
}

impl Block {
    pub fn null() -> Block {
        Block { to: Addr(0), from: Addr(0), message: [0; 512] }
    }

    pub fn from(&mut self, address: Addr) {
        self.from = address;
    }

    pub fn to(&mut self, address: Addr) {
        self.to = address;
    }

    pub fn message_str(&mut self, message: &str) {
        let mut index = 0;

        for letter in message.bytes() {
            if index == 512 {
                break;
            } else {
                self.message[index] = letter;
                index += 1;
            }
        }
    }

    pub fn message_vec(&mut self, message: &Vec<u8>) {
        let mut index = 0;

        for letter in message.iter() {
            if index == 512 {
                break;
            } else {
                self.message[index] = *letter;
                index += 1;
            }
        }
    }

    pub fn message(&self) -> Vec<u8> {
        self.message.to_vec()
    }

    pub fn to_bytes(&self) -> [u8; 544] {
        let mut bytes = [0; 544];
        let mut index = 0;

        for byte in self.to.0.to_le_bytes() {
            bytes[index] = byte;
            index += 1;
        }

        for byte in self.from.0.to_le_bytes() {
            bytes[index] = byte;
            index += 1;
        }

        for byte in self.message {
            bytes[index] = byte;
            index += 1;
        }

        bytes
    }

    pub fn from_bytes(bytes: [u8; 544]) -> Block {
        let mut block = Block::null();
        let mut index = 0;

        let mut to_bytes = [0; 16];

        for i in 0..16 {
            to_bytes[index] = bytes[i];
            index += 1;
        }
        index = 0;

        let mut from_bytes = [0; 16];

        for i in 16..32 {
            from_bytes[index] = bytes[i];
            index += 1;
        }
        index = 0;

        let mut message_bytes = [0; 512];

        for i in 32..544 {
            message_bytes[index] = bytes[i];
            index += 1;
        }

        block.to = Addr(u128::from_le_bytes(to_bytes));
        block.from = Addr(u128::from_le_bytes(from_bytes));

        block.message = message_bytes;

        block
    }
}

#[derive(Clone, Copy)]
#[repr(packed)]
pub struct Addr(u128);

impl Addr {
    pub fn new(address: u128) -> Addr {
        Addr(address)
    }
}