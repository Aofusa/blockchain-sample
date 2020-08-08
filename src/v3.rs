extern crate anyhow;
extern crate serde;
extern crate ring;
extern crate chrono;

use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use ring::{rand, digest};
use ring::signature::{self, KeyPair};
use chrono::{Utc, DateTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    sender_address: Vec<u8>,
    receiver_address: Vec<u8>,
    value: f32,
    sign: Vec<u8>,
}

trait Transact {
    fn str_data(&self) -> String;
}

impl Transact for Transaction {
    fn str_data(&self) -> String {
        let t = Transaction {
            sender_address: self.sender_address.clone(),
            receiver_address: self.receiver_address.clone(),
            value: self.value,
            sign: [].to_vec(),
        };
        serde_json::to_string(&t).unwrap()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Wallet {
    private_key: Vec<u8>,
    address: Vec<u8>,
}

impl Wallet {
    fn new() -> Wallet {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        Wallet {
            private_key: pkcs8_bytes.as_ref().to_owned(),
            address: key_pair.public_key().as_ref().to_owned(),
        }
    }
}

trait Deal {
    fn sign_transaction(&self, transaction: &Transaction) -> Transaction;
    fn send(&self, receiver_address: &[u8], value: f32) -> Transaction;
}

impl Deal for Wallet {
    fn sign_transaction(&self, transaction: &Transaction) -> Transaction {
        // generate signer from self private key
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(&self.private_key).unwrap();
        // hash the transaction
        let h = digest::digest(&digest::SHA512, &transaction.str_data().as_bytes());
        Transaction {
            sender_address: transaction.sender_address.clone(),
            receiver_address: transaction.receiver_address.clone(),
            value: transaction.value,
            sign: key_pair.sign(h.as_ref()).as_ref().to_vec(),
        }
    }

    fn send(&self, receiver_address: &[u8], value: f32) -> Transaction {
        let t = Transaction {
            sender_address: self.address.clone(),
            receiver_address: receiver_address.to_vec(),
            value: value,
            sign: [].to_vec(),
        };
        self.sign_transaction(&t)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Block {
    time: DateTime<Utc>,
    transactions: Vec<Transaction>,
    previous_hash: Vec<u8>,
    sign: Vec<u8>,
}

trait HashBlock {
    fn hash(&self) -> Vec<u8>;
}

impl HashBlock for Block {
    fn hash(&self) -> Vec<u8> {
        let b = Block {
            time: self.time,
            transactions: self.transactions.clone(),
            previous_hash: self.previous_hash.clone(),
            sign: [].to_vec(),
        };
        let s = serde_json::to_string(&b).unwrap();
        digest::digest(&digest::SHA512, s.as_bytes()).as_ref().to_owned()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TimestampServer {
    public_key: Vec<u8>,
    block_chain: Vec<Block>,
    signer: Vec<u8>,
}

impl TimestampServer {
    fn new() -> TimestampServer {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let mut chain = Vec::new();
        let genesis = Block {
            time: Utc::now(),
            transactions: Vec::new(),
            previous_hash: [].to_vec(),
            sign: [].to_vec(),
        };
        chain.push(genesis);
        TimestampServer {
            public_key: key_pair.public_key().as_ref().to_owned(),
            block_chain: chain,
            signer: pkcs8_bytes.as_ref().to_owned(),
        }
    }
}

trait BlockGenerator {
    fn generate_block(&mut self, transaction: &[Transaction]);
}

impl BlockGenerator for TimestampServer {
    fn generate_block(&mut self, transactions: &[Transaction]) {
        let mut tlist = Vec::new();
        tlist.extend_from_slice(transactions);
        let tlist = tlist;
        // generate block
        let block = Block {
            time: Utc::now(),
            transactions: tlist,
            previous_hash: self.block_chain.last().unwrap().hash(),
            sign: [].to_vec(),
        };
        // sign the block
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(self.signer.as_ref()).unwrap();
        let s = serde_json::to_string(&block).unwrap();
        let h = digest::digest(&digest::SHA512, s.as_bytes());
        let sign = key_pair.sign(h.as_ref()).as_ref().to_vec();
        let mut block = block;
        block.sign = sign;
        let block = block;
        // publish the block
        self.block_chain.push(block);
    }
}

fn verify_transaction(transaction: &Transaction) -> Result<(), Error> {
    if transaction.sign.is_empty() { return Err(anyhow!("transaction's sign is empty.")); }

    // hash the transaction
    let h = digest::digest(&digest::SHA512, &transaction.str_data().as_bytes());
    // generate verifier with public key
    let peer_public_key_bytes = &transaction.sender_address;
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
    // is the signature correct?
    match peer_public_key.verify(h.as_ref(), &transaction.sign) {
        Ok(_) => Ok(()),
        Err(_) => Err(anyhow!("invalid sign."))
    }
}

fn verify_block(previous_block: &Block, block: &Block, timestamp_server_publickey: &[u8]) -> bool {
    let is_correct_hash = previous_block.hash() == block.previous_hash;
    let is_correct_transactions = 
        block.transactions
        .iter()
        .filter(|x| verify_transaction(&x).is_err())
        .collect::<Vec<&Transaction>>()
        .is_empty();
    let h = block.hash();
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, timestamp_server_publickey);
    match peer_public_key.verify(h.as_ref(), &block.sign) {
        Ok(_) => is_correct_hash && is_correct_transactions,
        Err(_) => false
    }
}

fn verify_blockchain(chain: &[Block], timestamp_server_publickey: &[u8]) -> bool {
    for i in 0..chain.len()-1 {
        let index = chain.len()-i;
        if !verify_block(&chain[index-2], &chain[index-1], timestamp_server_publickey) { return false; }
    }
    true
}

fn main() {
    let mut timestamp_server = TimestampServer::new();

    let alice = Wallet::new();
    let bob = Wallet::new();

    let mut transactions = Vec::new();
    transactions.push(alice.send(&bob.address, 5.0));
    transactions.push(bob.send(&alice.address, 7.0));

    timestamp_server.generate_block(&transactions);

    let verify_result = verify_blockchain(&timestamp_server.block_chain, &timestamp_server.public_key);

    println!("timestamp server: {:?}", &timestamp_server);
    println!("verify: {:?}", verify_result);


    // 複数個のブロックを繋いでみる
    timestamp_server.generate_block(&transactions);
    timestamp_server.generate_block(&transactions);
    timestamp_server.generate_block(&transactions);
    timestamp_server.generate_block(&transactions);
    timestamp_server.generate_block(&transactions);
    let verify_result = verify_blockchain(&timestamp_server.block_chain, &timestamp_server.public_key);
    println!("timestamp server: {:?}", &timestamp_server);
    println!("verify: {:?}", verify_result);


    // ブロックの一つを書き換えてみる（verifyがfalseになる）
    timestamp_server.block_chain[3].transactions[0].value = 1.0;
    let verify_result = verify_blockchain(&timestamp_server.block_chain, &timestamp_server.public_key);
    println!("timestamp server: {:?}", &timestamp_server);
    println!("verify: {:?}", verify_result);
}

