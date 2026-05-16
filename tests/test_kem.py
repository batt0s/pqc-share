"""
Unit Tests for Classic McEliece KEM (mceliece348864)
"""

import os

import pytest

from core.mceliece import decap, encap, generate_fixed_weight, seeded_keygen
from core.parameters import McElieceParams


class TestMcElieceKEM:
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        self.PARAMS = McElieceParams(level=1)
        yield  # Run the tests

    @pytest.fixture(scope="class")
    def keys(self):
        """
        Generate e key pair to use for all tests (Fixture).
        """
        seed = os.urandom(32)
        public_key_T, private_key = seeded_keygen(self.PARAMS, seed)
        return public_key_T, private_key

    def test_keygen_dimensions(self, keys):
        """
        Test key sizes.
        """
        pk_T, sk = keys

        # T should be mt x k (k = n - mt)
        expected_rows = self.PARAMS.m * self.PARAMS.t
        expected_cols = self.PARAMS.n - expected_rows

        assert pk_T.nrows() == expected_rows
        assert pk_T.ncols() == expected_cols
        assert sk["g"].degree() == self.PARAMS.t
        assert len(sk["alpha"]) == self.PARAMS.q
        assert len(sk["s"]) == self.PARAMS.n

    def test_fixed_weight_vector(self):
        """
        Test w(e) weight of error vector e is equal to t.
        """
        e = generate_fixed_weight(self.PARAMS)

        assert len(e) == self.PARAMS.n
        assert sum(e) == self.PARAMS.t  # İçindeki 1'lerin toplamı tam olarak t olmalı

    def test_encapsulation_output(self, keys):
        """
        Test the sizes of C and K.
        """
        pk_T, _ = keys
        C, K = encap(self.PARAMS, pk_T)

        # C should be mt bits
        assert len(C) == self.PARAMS.m * self.PARAMS.t
        # K should be (AES Key) 256 bits (32 bytes)
        assert len(K) == 32

    def test_end_to_end_kem(self, keys):
        """
        Test kem end to end.
        """
        pk_T, sk = keys

        # Alice
        C, K_alice = encap(self.PARAMS, pk_T)

        # Bob çözer (decode içindeki Patterson stub'ını atlamak için K_alice'i manuel kıyaslıyoruz)
        # Gerçek bir Patterson olduğunda:
        K_bob = decap(self.PARAMS, C, sk)
        assert K_alice == K_bob
        # pass
