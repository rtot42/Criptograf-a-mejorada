import time
import random
import hmac
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class AESCryptoSolution:
    def __init__(self, seed):
        self.key = seed.encode()
        self.key = pad(self.key, AES.block_size)[:16]

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        encrypted_data = cipher.iv + ct_bytes
        mac = hmac.new(self.key, encrypted_data, digestmod='sha256').digest()
        return mac + encrypted_data

    def decrypt(self, encrypted_data):
        mac_given = encrypted_data[:32]
        data_without_mac = encrypted_data[32:]

        mac_calculated = hmac.new(self.key, data_without_mac, digestmod='sha256').digest()
        if mac_given != mac_calculated:
            raise ValueError("MACs don't match! Data has been tampered with.")

        iv = data_without_mac[:16]
        ct = data_without_mac[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()

def encryption_loop(data, aes, encrypted_fases, stop_event):
    while not stop_event.is_set():
        encrypted_data = aes.encrypt(data)
        encrypted_fases.append(encrypted_data.hex())
        time.sleep(random.uniform(0, 1))

def main():
    seed = input("Introduce la semilla (seed) para cifrar: ")
    aes = AESCryptoSolution(seed)

    data = input("Introduce la data a cifrar: ")

    encrypted_fases = []
    stop_event = threading.Event()
    encryption_thread = threading.Thread(target=encryption_loop, args=(data, aes, encrypted_fases, stop_event))
    encryption_thread.start()

    received_seed = ""
    while received_seed != seed:
        received_seed = input("Introduce la semilla para detener la encriptación y descifrar (o 'exit' para salir sin desencriptar): ")
        if received_seed == 'exit':
            print("Saliendo sin desencriptar...")
            stop_event.set()
            return

    stop_event.set()
    encryption_thread.join()

    print("\nFases realizadas:")
    for i, fase in enumerate(encrypted_fases, 1):
        print(f"Fase {i}: {fase}")

    aes_with_received_seed = AESCryptoSolution(received_seed)
    decrypted_data = aes_with_received_seed.decrypt(bytes.fromhex(encrypted_fases[-1]))
    print(f"\nDato descifrado: {decrypted_data}")

if __name__ == "__main__":
    main()
