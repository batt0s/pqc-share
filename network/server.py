"""PQC-Share Server (Receiver)"""

import os
import pickle
import socket

from core.mceliece import decap, seeded_keygen
from core.parameters import PARAMS
from crypto.cipher import decrypt_file
from network.utils import recv_msg, send_msg


def start_server(host="0.0.0.0", port=65432, output_filename="received_secret.txt"):
    # 1. Key Generation (TODO: Save and read the key from a file like ~/.pqc_share)
    print("[*] (KEM) Generating keys...")
    seed = os.urandom(32)
    pk_T, sk = seeded_keygen(PARAMS, seed)
    print("[+] Keys generated!")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"[*] Listening on {host}:{port}...")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection esthablished: {addr}")

            # 2. Send the Public Key
            print("[*] Sending public key...")
            send_msg(conn, pickle.dumps(pk_T))

            # 3. Recieve the encrypted capsule (C)
            print("[*] Waiting for the capsule...")
            c_data = recv_msg(conn)
            C = pickle.loads(c_data)

            # 4. Decapsulation (Extract the AES Key using Patterson Algorithm)
            print("[*] Decapsulation in progress...")
            K_list = decap(PARAMS, C, sk)
            if not K_list:
                print("[-] ERROR: Decapsulation error!")
                return
            K = bytes(K_list)
            print("[+] Common AES Key (K) generated succesfully!")

            # 5. Recieve the file (Chunking over TCP)
            print("[*] Recieving the file...")
            enc_filepath = output_filename + ".enc"
            with open(enc_filepath, "wb") as f:
                while True:
                    chunk = recv_msg(conn)
                    # EOF (empty message)
                    if not chunk or len(chunk) == 0:
                        break
                    f.write(chunk)

            # 6. Decrypt the file and check integrity (tag)
            print("[*] Decrypting the file...")
            decrypt_file(K, enc_filepath, output_filename)
            print(f"[+] Decryption succesfull. File saved as: {output_filename}")

            # Cleaning
            os.remove(enc_filepath)
