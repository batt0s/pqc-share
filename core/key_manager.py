"""Key Management Module"""

import getpass
import os
from pathlib import Path

from core.encoder import (
    export_private_key,
    export_public_key,
    import_private_key,
    import_public_key,
)
from core.mceliece import seeded_keygen
from core.parameters import McElieceParams


def get_or_create_keys(params: McElieceParams, key_dir="~/.pqc_share/keys"):
    """
    Read the key pair if exists, create and save if not.
    """
    pqc_dir = Path(key_dir).expanduser()
    pqc_dir.mkdir(parents=True, exist_ok=True)

    pub_path = pqc_dir / f"public_key_l{params.level}.pub"
    priv_path = pqc_dir / f"private_key_l{params.level}.pem"

    if pub_path.exists() and priv_path.exists():
        print(f"[*] Loading the key pair from file ({pqc_dir})...")
        passphrase = getpass.getpass("[?] Enter the passphrase for the private key: ")
        with open(pub_path, "rb") as f:
            pk_T = import_public_key(f.read(), params)
        with open(priv_path, "rb") as f:
            sk = import_private_key(f.read(), params, passphrase)
        return pk_T, sk
    else:
        print(f"[*] Could not found the key pair in {pqc_dir}.")
        print("[*] Generating a key pair... ")

        passphrase = getpass.getpass("[?] Enter a passphrase for the private key: ")
        passphrase_confirm = getpass.getpass("[?] Confirm the passphrase: ")
        if passphrase != passphrase_confirm:
            raise ValueError("[!] Passphrases do not match.")

        print(
            "[*] Generating a key pair... (This could take some time depending on the security level)"
        )

        seed = os.urandom(32)
        pk_T, sk = seeded_keygen(params, seed)

        with open(pub_path, "wb") as f:
            f.write(export_public_key(pk_T, params))
        with open(priv_path, "wb") as f:
            f.write(export_private_key(sk, passphrase))

        print(f"[+] Succesfully generated a key pair and saved to {key_dir}.")
        return pk_T, sk
