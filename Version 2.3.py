import hashlib
import time
import json
from urllib.parse import urlparse
from uuid import uuid4
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
import requests
from concurrent.futures import ThreadPoolExecutor

class Transaction:
    def __init__(self, sender, recipient, amount, fee, sender_public_key):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.fee = fee
        self.sender_public_key = sender_public_key
        self.signature = None
        self.timestamp = time.time()
        self.confirmation_time = None  # New field for confirmation time

    def sign_transaction(self, private_key):
        transaction_hash = self.get_transaction_hash()
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        signature = sk.sign(transaction_hash.encode('utf-8'))
        self.signature = signature.hex()
        
    def confirm_transaction(self):
        self.confirmation_time = time.time()
        #print(f"Transaction {self.get_transaction_hash()} confirmed at: {self.confirmation_time}")
    

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "fee": self.fee,
            "sender_public_key": self.sender_public_key,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "confirmation_time": self.confirmation_time  # Include confirmation time in the dictionary
        }

    def get_transaction_hash(self):
        return hashlib.sha256(
            (str(self.sender) + str(self.recipient) + str(self.amount) + str(self.fee) +
             str(self.sender_public_key)).encode('utf-8')).hexdigest()

class SmartContractTransaction(Transaction):
    def __init__(self, sender, contract_address, gas_fee, sender_public_key):
        super().__init__(sender, contract_address, 0, gas_fee, sender_public_key)
        self.contract_address = contract_address

    def sign_transaction(self, private_key):
        transaction_hash = self.get_transaction_hash()
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        signature = sk.sign(transaction_hash.encode('utf-8'))
        self.signature = signature.hex()

    def to_dict(self):
        transaction_dict = super().to_dict()
        transaction_dict["contract_address"] = self.contract_address
        return transaction_dict

class TokenTransferTransaction(Transaction):
    def __init__(self, sender, recipient, amount, fee, sender_public_key, token_contract_address):
        super().__init__(sender, token_contract_address, 0, fee, sender_public_key)
        self.token_contract_address = token_contract_address
        self.amount = amount

    def sign_transaction(self, private_key):
        transaction_hash = self.get_transaction_hash()
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        signature = sk.sign(transaction_hash.encode('utf-8'))
        self.signature = signature.hex()

    def to_dict(self):
        transaction_dict = super().to_dict()
        transaction_dict["token_contract_address"] = self.token_contract_address
        return transaction_dict

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        transaction_list = [tx.to_dict() for tx in self.transactions]
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": transaction_list,
            "nonce": self.nonce
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode('utf-8')).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.nodes = set()
        self.difficulty = 4
        self.mining_reward = 1.0
        self.transactions_processed = 0
        self.start_time = time.time()
        self.adjustment_interval = 60
        self.mining_durations = []  # List to store mining durations for adjustment
        self.latencies = []  # List to store individual latencies

    def create_genesis_block(self):
        return Block(0, "0", time.time(), [])
    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def has_enough_balance(self, sender, required_balance):
        # Placeholder implementation, you should replace this with your actual balance retrieval logic
        balances = {"Alice": 100, "Bob": 50, "SmartContract123": 1000, "TokenContract456": 500}
        if sender in balances and balances[sender] >= required_balance:
            return True
        else:
            print(f"Insufficient balance for sender: {sender}")
            return False
        
    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block.previous_hash != self.hash(last_block):
                return False

            if not self.valid_proof(last_block.nonce, block.nonce, last_block.hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbors = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbors:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def hash(self, block):
        return hashlib.sha256(json.dumps(block.__dict__, sort_keys=True, default=self.custom_serializer).encode()).hexdigest()
    
    def custom_serializer(self, obj):
        if isinstance(obj, Transaction):
            return obj.to_dict()
        raise TypeError("Object not serializable")

    def proof_of_work(self, last_nonce):
        nonce = 0
        while not self.valid_proof(last_nonce, nonce, self.hash(self.chain[-1])):
            nonce += 1
        return nonce

    def valid_proof(self, last_nonce, nonce, last_hash):
        guess = f'{last_nonce}{nonce}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == '0' * self.difficulty

    def mine(self, num_blocks_to_mine, max_transactions_per_block):
        total_transactions_processed = 0
        total_elapsed_time = 0
        nodes = list(self.nodes)  # Convert set of nodes to a list
    
        for _ in range(num_blocks_to_mine):
            for node_address in nodes:
                # Record the starting time
                start_time = time.time()
    
                # Check if there are pending transactions to mine
                if not self.pending_transactions:
                    print("No more pending transactions. Exiting mining process.")
                    # Print statistics related to the current performance
                    self.print_current_statistics(total_transactions_processed, total_elapsed_time)
                    return
    
                reward_transaction = Transaction("system", node_address, self.mining_reward, 0, "")
                self.pending_transactions.append(reward_transaction)
    
                last_block = self.chain[-1]
                index = last_block.index + 1
    
                # Adjust the number of transactions to include in each block
                transactions_to_include = [reward_transaction] + self.pending_transactions[:max_transactions_per_block - 1]
                self.pending_transactions = self.pending_transactions[max_transactions_per_block:]
    
                timestamp_start = time.time()
                nonce = self.proof_of_work(last_block.nonce)
    
                mining_duration = time.time() - start_time  # Calculate the elapsed time
                self.mining_durations.append(mining_duration)
    
                new_block = Block(index, last_block.hash, timestamp_start, transactions_to_include, nonce)
                self.chain.append(new_block)
                confirmation_times = []  # List to store confirmation times
    
                transactions_processed = len(transactions_to_include)
                total_transactions_processed += transactions_processed
    
                # Remove transactions included in the mined block from pending transactions
                for transaction in transactions_to_include:
                    if transaction in self.pending_transactions:
                        self.pending_transactions.remove(transaction)
    
                    transaction.confirm_transaction()
                    confirmation_time = transaction.confirmation_time - transaction.timestamp
                    confirmation_times.append(confirmation_time)
                    print(f"Transaction confirmed in {confirmation_time * 1000:.2f} milliseconds")
    
                elapsed_time = time.time() - start_time
                total_elapsed_time += elapsed_time
    
                # Print block information
                print(f"Block {index} mined by node {node_address}:")
                print(f"Hash: {new_block.hash}")
                print(f"Timestamp: {new_block.timestamp}")
                print(f"Transactions: {transactions_processed}")
                print()
    
        # Calculate total throughput
        total_throughput = total_transactions_processed / total_elapsed_time
        print(f"____Total Throughput: {total_throughput:.4f} transactions per second")
        print(f"____Total Number of Transactions: {total_transactions_processed}")
        print("Mining process completed.")
    
        return new_block
    
    def print_current_statistics(self, total_transactions_processed, total_elapsed_time):
        # Calculate total throughput for the current performance
        current_throughput = total_transactions_processed / total_elapsed_time
        print(f"____Current Throughput: {current_throughput:.4f} transactions per second")
        print(f"____Total Number of Transactions Processed: {total_transactions_processed}")
        print("Current performance statistics printed.")


    def adjust_difficulty(self):
        # Calculate the average mining duration over the last 10 blocks
        average_mining_duration = sum(self.mining_durations) / len(self.mining_durations)
        
        # Adjust difficulty based on mining performance
        target_duration = self.adjustment_interval
        adjustment_factor = target_duration / average_mining_duration
    
        if adjustment_factor > 1.5:
            # If mining is too fast, increase difficulty
            self.difficulty += 1
        elif adjustment_factor < 0.5:
            # If mining is too slow, decrease difficulty
            self.difficulty -= 1
    
        # Ensure difficulty is within a reasonable range (e.g., between 1 and 10)
        self.difficulty = max(1, min(10, self.difficulty))
    
        print(f"Difficulty adjusted to: {self.difficulty}")


    def add_transaction(self, sender, recipient, amount, fee, sender_public_key, sender_private_key):
        # Log timestamp when the transaction is submitted
        submission_time = time.time()
        #print(f"Transaction submitted at: {submission_time}")
        # Validate sender has enough balance
        if not self.has_enough_balance(sender, amount + fee):
            print("Transaction failed: Sender does not have enough balance.")
            return -1
        
        # Create a new transaction
        transaction = Transaction(sender, recipient, amount, fee, sender_public_key)
        transaction.sign_transaction(sender_private_key)
    
               
        # Add the transaction to the pending transactions

        self.pending_transactions.append(transaction)
        processing_time = time.time() - submission_time
        
        # Log individual latency
        self.latencies.append(processing_time)
        
        # Log timestamp when the transaction is processed
        processing_completion_time = time.time()
        print(f"Transaction processed in {processing_time * 1000:.2f} milliseconds")

        #print(f"Transaction processing completed at: {processing_completion_time* 1000:.2f}")

        return self.last_block.index + 1
    
    def print_average_latency(self):
        if self.latencies:
            average_latency = sum(self.latencies) / len(self.latencies)
            print(f"___Average Latency: {average_latency:.6f} seconds")
        else:
            print("No transactions processed yet.")

    def generate_transactions(self, num_transactions, sender, recipient, amount, fee, sender_public_key, sender_private_key):
        with ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(self.add_transaction, sender, recipient, amount, fee, sender_public_key, sender_private_key)
                for _ in range(num_transactions)
            ]

            for future in futures:
                future.result()

    @property
    def last_block(self):
        return self.chain[-1]

# Example usage:
blockchain = Blockchain()
candidate_node_address = str(uuid4())

# Register nodes
node_addresses = ["http://localhost:5001", "http://localhost:5002", "http://localhost:5003", "http://localhost:5004",
                  "http://localhost:5005", "http://localhost:5006", "http://localhost:5007", "http://localhost:5008"]
for address in node_addresses:
    blockchain.register_node(address)

# Add transactions
alice_private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
alice_public_key = '04a3c3c7a9b605ebc62c0415f5c8d088f2a5eeefc3c740d3a883833f24484a978d8b21d9d2d02a5d9a84221c1dd1d6c6b04bc828abac6f74e16a8a9d5ad900c'

blockchain.add_transaction("Alice", "AAA", 2.0, 0.1, alice_public_key, alice_private_key)
blockchain.add_transaction("Alice", "BBB", 2.0, 0.1, alice_public_key, alice_private_key)
blockchain.add_transaction("Alice", "CCC", 2.0, 0.1, alice_public_key, alice_private_key)
blockchain.add_transaction("Alice", "DDD", 2.0, 0.1, alice_public_key, alice_private_key)
blockchain.add_transaction("Alice", "EEE", 2.0, 0.1, alice_public_key, alice_private_key)
blockchain.add_transaction("Alice", "FFF", 2.0, 0.1, alice_public_key, alice_private_key)
blockchain.add_transaction("Alice", "GGG", 2.0, 0.1, alice_public_key, alice_private_key)

#blockchain.generate_transactions(20, "Alice", "Bob", 2.0, 0.1, alice_public_key, alice_private_key)

mined_block = blockchain.mine( 3, 4)  # HOW TO SELECT THE MINER?????

for block in blockchain.chain:
    print(f"Block {block.index}:")
    print(f"Hash: {block.hash}")
    print(f"Timestamp: {block.timestamp}")
    print(f"Transactions: {len(block.transactions)}")
    for tx in block.transactions:
        print(f"  - From: {tx.sender}, To: {tx.recipient}, Amount: {tx.amount}, Fee: {tx.fee}")
        if isinstance(tx, SmartContractTransaction):
            print(f"    - Smart Contract Interaction: Contract Address: {tx.contract_address}")
        elif isinstance(tx, TokenTransferTransaction):
            print(f"    - Token Transfer: Token Contract Address: {tx.token_contract_address}")
    print("\n")

print(f"Number of nodes: {len(blockchain.nodes)}")
print(f"Number of transactions: {blockchain.transactions_processed}")
blockchain.print_average_latency()

