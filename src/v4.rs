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
    nonce: u32,
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
            nonce: self.nonce,
        };
        let s = serde_json::to_string(&b).unwrap();
        digest::digest(&digest::SHA512, s.as_bytes()).as_ref().to_owned()
    }
}

type BlockChain = Vec<Block>;

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

fn verify_block(previous_block: &Block, block: &Block) -> bool {
    let is_correct_hash = previous_block.hash() == block.previous_hash;
    let is_correct_transactions = 
        block.transactions
        .iter()
        .filter(|x| verify_transaction(&x).is_err())
        .collect::<Vec<&Transaction>>()
        .is_empty();
    let is_correct_proof = valid_proof(block).is_ok();
    is_correct_hash && is_correct_transactions && is_correct_proof
}

const DIFFICULTY: usize = 1;
fn valid_proof(block: &Block) -> Result<(), Error> {
    let h = block.hash();
    for i in 0..DIFFICULTY {
        if h[i] != 0 {
            return Err(anyhow!("invalid nonce."));
        }
    }
    Ok(())
}

fn mine(block: &Block) -> Block {
    let mut nonce: u32 = 0;
    let mut b = Block {
        time: block.time,
        transactions: block.transactions.clone(),
        previous_hash: block.previous_hash.clone(),
        nonce: nonce,
    };
    eprint!("\rMining Block (nonce = {:?}, hash = {:?})\x1b[0K", nonce, b.hash());
    while valid_proof(&b).is_err() {
        nonce += 1;
        b.nonce = nonce;
        eprint!("\rMining Block (nonce = {:?}, hash = {:?})\x1b[0K", nonce, b.hash());
    }
    b
}

fn main() {
    let alice = Wallet::new();
    let bob = Wallet::new();

    let mut block_chain = BlockChain::new();
    let genesis = Block {
        time: Utc::now(),
        transactions: Vec::new(),
        previous_hash: [].to_vec(),
        nonce: 0,
    };
    block_chain.push(genesis);

    // 取引
    let mut transactions = Vec::new();
    transactions.push(alice.send(&bob.address, 5.0));
    transactions.push(bob.send(&alice.address, 7.0));

    // ブロックの追加
    let previous_hash = block_chain.last().unwrap().hash();
    let t_block = Block {
        time: Utc::now(),
        transactions: transactions,
        previous_hash: previous_hash,
        nonce: 0,
    };
    let block = mine(&t_block);
    let verify_result = verify_block(block_chain.last().unwrap(), &block);
    println!("Block nonce: {:?}", block.nonce);
    println!("Block hash: {:?}", block.hash());
    println!("Difficulty: {:?}", DIFFICULTY);
    println!("verify: {:?}", verify_result);

    block_chain.push(block);
    println!("Block chain: {:?}", &block_chain);
}

