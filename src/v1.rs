#[derive(Debug)]
struct Transaction {
    sender_address: i32,
    receiver_address: i32,
    value: f32
}

#[derive(Debug)]
struct Wallet {
    address: i32,
}

trait Send {
    fn send(&self, receiver_address: i32, value: f32) -> Transaction;
}

impl Send for Wallet {
    fn send(&self, receiver_address: i32, value: f32) -> Transaction {
        return Transaction {
            sender_address: self.address,
            receiver_address: receiver_address,
            value: value,
        };
    }
}

type Ledger = Vec<Transaction>;

fn main() {
    let alice = Wallet {address: 1};
    let bob = Wallet {address: 2};
    let mut ledger = Ledger::new();

    let transaction = alice.send(bob.address, 5.0);
    ledger.push(transaction);

    for item in ledger {
        println!("Transaction: {:?}", item);
    }
}

