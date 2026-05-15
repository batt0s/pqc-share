"""PQC-Share Client (Sender)"""

import os
import pickle
import socket

from core.mceliece import encap
from core.parameters import PARAMS
from crypto.cipher import encrypt_file
from network.utils import recv_msg, send_msg


def send_file(target_ip, target_port, file_to_send):
    if not os.path.exists(file_to_send):
        print(f"[-] ERROR: File could not found ({file_to_send})")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[*] Connecting {target_ip}:{target_port}...")
        s.connect((target_ip, target_port))

        # 1. Recieve the Public Key
        print("[*] Waiting for Public Key...")
        pk_data = recv_msg(s)
        pk_T = pickle.loads(pk_data)

        # 2. Encapsulation
        print("[*] Encapsulation in progress...")
        C, K_list = encap(PARAMS, pk_T)
        K = bytes(K_list)

        # 3. Send the capsule
        print("[*] Sending Encrypted Capsule (C)...")
        send_msg(s, pickle.dumps(C))

        # 4. Encrypt the file with AES-GCM
        print(f"[*] Encryption in progress... ('{file_to_send}')")
        enc_filepath = file_to_send + ".enc"
        encrypt_file(K, file_to_send, enc_filepath)

        # 5. Send files (chunks over socket)
        print("[*] Sending the encrypted file...")
        with open(enc_filepath, "rb") as f:
            while chunk := f.read(64 * 1024):
                send_msg(s, chunk)

        # EOF
        send_msg(s, b"")

        print("[+] Done!")

        os.remove(enc_filepath)
