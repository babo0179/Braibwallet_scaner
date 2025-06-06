import hashlib
from bitcoinlib.keys import Key
import requests
import time
import random

def private_key_from_passphrase(passphrase):
    return hashlib.sha256(passphrase.encode('utf-8')).hexdigest()

def get_address_from_private_key(private_key_hex):
    key = Key(private_key_hex)
    return key.address()

def get_balance_blockstream(address):
    url = f"https://blockstream.info/api/address/{address}"
    max_retries = 5
    for attempt in range(max_retries):
        response = requests.get(url)
        print(f"Checking address: {address}")
        print(f"Response status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            chain_balance = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
            mempool_balance = data.get('mempool_stats', {}).get('funded_txo_sum', 0) - data.get('mempool_stats', {}).get('spent_txo_sum', 0)
            total_balance = (chain_balance + mempool_balance) / 1e8
            print(f"Balance: {total_balance} BTC")
            return total_balance
        elif response.status_code == 429:
            wait_time = random.uniform(5, 15)
            print(f"Rate limited, retrying after {wait_time:.2f} seconds...")
            time.sleep(wait_time)
        else:
            print(f"HTTP error {response.status_code}")
            return None
    print(f"Failed to fetch balance for {address} after {max_retries} retries.")
    return None

def main():
    with open("brainwallet_wordlist1.txt", "r", encoding='utf-8') as file:
        checked_addresses = set()
        for line in file:
            passphrase = line.strip()
            if not passphrase:
                continue
            priv_key = private_key_from_passphrase(passphrase)
            address = get_address_from_private_key(priv_key)
            if address in checked_addresses:
                continue
            checked_addresses.add(address)
            balance = get_balance_blockstream(address)
            if balance is None:
                print(f"Error fetching balance for {address}")
            elif balance > 0:
                print(f"Passphrase: {passphrase}\nAddress: {address}\nBalance: {balance} BTC\n{'-'*40}")
            time.sleep(random.uniform(1, 3))

if __name__ == "__main__":
    main()
