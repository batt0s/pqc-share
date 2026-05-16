"""
Unit Tests for AES-256-GCM File Encryption
"""

import os

import pytest
from cryptography.exceptions import InvalidTag

from crypto.cipher import decrypt_file, encrypt_file


class TestAESGCM:
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        self.key = os.urandom(32)  # 256-bit dummy McEliece KEM key
        self.plain_file = "test_plain.txt"
        self.enc_file = "test_enc.bin"
        self.dec_file = "test_dec.txt"

        # Create a 1MB file
        with open(self.plain_file, "wb") as f:
            f.write(os.urandom(1024 * 1024))

        yield  # Run the tests

        # Delete the files
        for f in [self.plain_file, self.enc_file, self.dec_file]:
            if os.path.exists(f):
                os.remove(f)

    def test_encryption_decryption_success(self):
        encrypt_file(self.key, self.plain_file, self.enc_file)
        assert os.path.exists(self.enc_file)

        result = decrypt_file(self.key, self.enc_file, self.dec_file)
        assert result is True

        with open(self.plain_file, "rb") as f1, open(self.dec_file, "rb") as f2:
            assert f1.read() == f2.read()

    def test_tamper_detection(self):
        encrypt_file(self.key, self.plain_file, self.enc_file)

        with open(self.enc_file, "r+b") as f:
            f.seek(500)
            original_byte = f.read(1)
            f.seek(500)
            # inverse byte (XOR)
            f.write(bytes([original_byte[0] ^ 0xFF]))

        with pytest.raises(InvalidTag):
            decrypt_file(self.key, self.enc_file, self.dec_file)
