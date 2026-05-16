"""
PQC-Crypto Module
Handles AES-256-GCM encryption and decryption of large files using memory-efficient chunking.
"""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constants
CHUNK_SIZE = 64 * 1024
NONCE_SIZE = 12
TAG_SIZE = 16


def encrypt_file(key: bytes, input_filepath: str, output_filepath: str) -> None:
    """
    Encrypt file with AES-256-GCM.
    Returns: [12-bype Nonce] + [Encrypted data blocks] + [16-byte Integrity Tag]
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires exactly a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    with open(input_filepath, "rb") as f_in, open(output_filepath, "wb") as f_out:
        f_out.write(nonce)

        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            ciphertext_chunk = encryptor.update(chunk)
            f_out.write(ciphertext_chunk)

        encryptor.finalize()

        f_out.write(encryptor.tag)


def decrypt_file(key: bytes, input_filepath: str, output_filepath: str) -> bool:
    """
    Decrypt and check the integrty of a file encrypted with AES-256-GCM.
    Even if one bit is changed, throws a InvalidTag error.
    """
    file_size = os.path.getsize(input_filepath)
    if file_size < NONCE_SIZE + TAG_SIZE:
        raise ValueError("File is too small to be a valid ciphertext.")

    with open(input_filepath, "rb") as f_in:
        nonce = f_in.read(NONCE_SIZE)

        f_in.seek(-TAG_SIZE, os.SEEK_END)
        tag = f_in.read(TAG_SIZE)

        ciphertext_size = file_size - NONCE_SIZE - TAG_SIZE

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()

        f_in.seek(NONCE_SIZE)

        with open(output_filepath, "wb") as f_out:
            bytes_read = 0
            while bytes_read < ciphertext_size:
                read_size = min(CHUNK_SIZE, ciphertext_size - bytes_read)
                chunk = f_in.read(read_size)

                f_out.write(decryptor.update(chunk))
                bytes_read += len(chunk)

            decryptor.finalize()

    return True
