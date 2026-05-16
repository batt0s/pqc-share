"""PQC-Share Server (Receiver)"""

import os
import socket

from tqdm import tqdm

from core.encoder import export_public_key, import_ciphertext
from core.key_manager import get_or_create_keys
from core.mceliece import decap
from core.parameters import McElieceParams
from crypto.cipher import decrypt_file
from network.utils import recv_msg, send_msg


def start_server(
    params: McElieceParams,
    host: str = "0.0.0.0",
    port: int = 65432,
    output_filename: str = "received_secret.txt",
):
    # 1. Read or generate the key pair
    pk_T, sk = get_or_create_keys(params)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"[*] Listening on {host}:{port}...")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection esthablished: {addr}")

            # 2. Send the Public Key
            print("[*] Sending public key...")
            pem_bytes = export_public_key(pk_T, params)
            send_msg(conn, pem_bytes)

            # 3. Recieve the encrypted capsule (C)
            print("[*] Waiting for the capsule...")
            c_data = recv_msg(conn)
            C = import_ciphertext(c_data, params)

            # 4. Decapsulation (Extract the AES Key using Patterson Algorithm)
            print("[*] Decapsulation in progress...")
            K_list = decap(params, C, sk)
            if not K_list:
                print("[-] ERROR: Decapsulation error!")
                return
            K = bytes(K_list)
            print("[+] Common AES Key (K) generated succesfully!")

            # 5. Recieve the file (Chunking over TCP)
            print("[*] Recieving the file...")
            enc_filepath = output_filename + ".enc"
            with open(enc_filepath, "wb") as f:
                with tqdm(
                    desc=f"[+] Downloading file: {output_filename}",
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                ) as pbar:
                    while True:
                        chunk = recv_msg(conn)
                        # EOF (empty message)
                        if not chunk or len(chunk) == 0:
                            break
                        f.write(chunk)
                        pbar.update(len(chunk))

            # 6. Decrypt the file and check integrity (tag)
            print("[*] Decrypting the file...")
            decrypt_file(K, enc_filepath, output_filename)
            print(f"[+] Decryption succesfull. File saved as: {output_filename}")

            # Cleaning
            os.remove(enc_filepath)
