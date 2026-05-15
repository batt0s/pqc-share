"""Key Management Module"""

import os
import pickle
from pathlib import Path

from core.encoder import (
    export_private_key,
    export_public_key,
    import_private_key,
    import_public_key,
)
from core.mceliece import seeded_keygen
from core.parameters import PARAMS


def get_or_create_keys(key_dir="~/.pqc_share/keys"):
    """
    Read the key pair if exists, create and save if not.
    """
    pqc_dir = Path(key_dir).expanduser()
    pqc_dir.mkdir(parents=True, exist_ok=True)

    pub_path = pqc_dir / "public_key.pub"
    priv_path = pqc_dir / "private_key.pem"

    if pub_path.exists() and priv_path.exists():
        print(f"[*] Loading the key pair from file ({pqc_dir})...")
        with open(pub_path, "rb") as f:
            pk_T = import_public_key(f.read(), PARAMS)
        with open(priv_path, "rb") as f:
            sk = import_private_key(f.read(), PARAMS)
        return pk_T, sk
    else:
        print(f"[*] Could not found the key pair in {pqc_dir}.")
        print("[*] Generating a key pair... (This could take some time)")

        seed = os.urandom(32)
        pk_T, sk = seeded_keygen(PARAMS, seed)

        with open(pub_path, "wb") as f:
            f.write(export_public_key(pk_T, PARAMS))
        with open(priv_path, "wb") as f:
            f.write(export_private_key(sk))

        print(f"[+] Succesfully generated a key pair and saved to {key_dir}.")
        return pk_T, sk
