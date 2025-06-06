import hashlib
from bitcoinlib.keys import Key
import requests
import time

def private_key_from_passphrase(passphrase):
    hashed = hashlib.sha256(passphrase.encode('utf-8')).digest()
    return hashed

def get_address_from_private_key(private_key_bytes):
    key = Key(private_key_bytes)
    return key.address()

def get_balance(address):
    url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
    response = requests.get(url)
    print(f"Checking address: {address}")
    print(f"Response status: {response.status_code}")
    print(f"Response text: {response.text}")
    if response.status_code == 200:
        data = response.json()
        return data.get('final_balance', 0) / 1e8
    else:
        return None

def main():
    with open("brainwallet_wordlist.txt", "r", encoding='utf-8') as file:
        for line in file:
            passphrase = line.strip()
            if not passphrase:
                continue
            priv_key = private_key_from_passphrase(passphrase)
            address = get_address_from_private_key(priv_key)
            balance = get_balance(address)
            time.sleep(5)  # API রেট লিমিটের জন্য
            if balance is None:
                print(f"Error fetching balance for {address}")
            elif balance > 0:
                print(f"Passphrase: {passphrase}\nAddress: {address}\nBalance: {balance} BTC\n{'-'*40}")

if __name__ == "__main__":
    main()
