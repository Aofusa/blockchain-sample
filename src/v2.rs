extern crate anyhow;
extern crate serde;
extern crate ring;

use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use ring::{rand, digest};
use ring::signature::{self, KeyPair};

#[derive(Debug, Serialize, Deserialize)]
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

type Ledger = Vec<Transaction>;

fn verify_transaction(transaction: &Transaction) -> Result<(), Error> {
    if transaction.sign.is_empty() { return Err(anyhow!("transaction's sign is empty.")); }

    // hash the transaction
    let h = digest::digest(&digest::SHA512, &transaction.str_data().as_bytes());
    // generate verifier with public key
    let peer_public_key_bytes = &transaction.sender_address;
    let peer_public_key =
    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
    // is the signature correct?
    match peer_public_key.verify(h.as_ref(), &transaction.sign) {
        Ok(_) => Ok(()),
        Err(_) => Err(anyhow!("invalid sign."))
    }
}

fn main() {
    let alice = Wallet::new();
    let bob = Wallet::new();
    let mut ledger = Ledger::new();

    let transaction = alice.send(&bob.address, 5.0);
    ledger.push(transaction);

    for item in &ledger {
        println!("Transaction: {:?}", item);
        match verify_transaction(&item) {
            Ok(_) => println!("valid."),
            Err(_) => println!("invalid."),
        }
    }

    for item in &mut ledger {
        item.value = 7.0;
        println!("Transaction: {:?}", item);
        match verify_transaction(&item) {
            Ok(_) => println!("valid."),
            Err(_) => println!("invalid."),
        }
    }
}

