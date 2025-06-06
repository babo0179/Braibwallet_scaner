import hashlib
import base58
import socket
import json
import time
from bitcoinlib.keys import Key

ELECTRUM_SERVER = ("electrum.blockstream.info", 50001)  # TCP Electrum server

def private_key_from_passphrase(passphrase):
    hashed = hashlib.sha256(passphrase.encode('utf-8')).digest()
    return hashed

def get_address_from_private_key(private_key_bytes):
    key = Key(private_key_bytes)
    return key.address()

def p2pkh_scriptPubKey(address):
    decoded = base58.b58decode_check(address)
    pubkey_hash = decoded[1:]
    script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
    return script

def address_to_scripthash(address):
    if address.startswith('1'):
        script = p2pkh_scriptPubKey(address)
    else:
        print(f"Only Legacy (1...) addresses supported now: {address}")
        return None
    h = hashlib.sha256(script).digest()
    return h[::-1].hex()  # reversed hex string

def electrum_request(method, params, request_id=1):
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params
    }
    return json.dumps(request) + "\n"

def get_balance_electrum(address):
    scripthash = address_to_scripthash(address)
    if scripthash is None:
        return None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(ELECTRUM_SERVER)
        req = electrum_request("blockchain.scripthash.get_balance", [scripthash])
        s.sendall(req.encode())
        
        data = b""
        while True:
            part = s.recv(4096)
            if not part:
                break
            data += part
            if b"\n" in part:
                break

        response = json.loads(data.decode())
        if 'result' in response:
            confirmed = response['result']['confirmed']
            unconfirmed = response['result']['unconfirmed']
            total = (confirmed + unconfirmed) / 1e8
            return total
        else:
            return None

def main():
    with open("brainwallet_wordlist.txt", "r", encoding='utf-8') as file:
        for line in file:
            passphrase = line.strip()
            if not passphrase:
                continue
            print(f"Checking passphrase: {passphrase}")
            priv_key = private_key_from_passphrase(passphrase)
            address = get_address_from_private_key(priv_key)
            print(f"Address: {address}")
            balance = get_balance_electrum(address)
            if balance is None:
                print("Error fetching balance or unsupported address format.")
            elif balance > 0:
                print(f"Found balance! Passphrase: {passphrase}\nAddress: {address}\nBalance: {balance} BTC\n{'-'*40}")
            else:
                print("Balance: 0 BTC")
            time.sleep()  # Electrum rate limit এড়াতে একটু বিরতি

if __name__ == "__main__":
    main()
