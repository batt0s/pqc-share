"""
Security Module
Manages TOFU (Trust On First Use) fingerprint verification.
"""

import hashlib
from pathlib import Path


def get_fingerprint(public_key_bytes: bytes) -> str:
    """SSH Style SHA-256 fingerprint from the Public Key"""
    sha256_hash = hashlib.sha256(public_key_bytes).hexdigest()
    short_hash = sha256_hash[:32]
    return ":".join(short_hash[i : i + 2] for i in range(0, len(short_hash), 2))


def verify_host(
    target_host: str,
    selected_level: int,
    public_key_bytes: bytes,
    key_dir="~/.pqc_share",
) -> bool:
    pqc_dir = Path(key_dir).expanduser()
    known_pairs_path = pqc_dir / "known_pairs"

    fingerprint = get_fingerprint(public_key_bytes)

    if not known_pairs_path.exists():
        known_pairs_path.touch()

    known_hosts = {}
    with open(known_pairs_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and line.startswith("#"):
                continue
            host, level, fpr = line.split(" ", 2)
            if host not in known_hosts:
                known_hosts[host] = {}
            known_hosts[host][level] = fpr

    if target_host in known_hosts and selected_level in known_hosts[target_host]:
        if known_hosts[target_host][selected_level] == fingerprint:
            return True  # Recognized, fingerprint matched, safe.
        else:
            print("\n" + "=" * 65)
            print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            print("@       WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!        @")
            print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            print("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!")
            print("Someone could be eavesdropping on you right now (MITM attack)!")
            print(f"Host: {target_host}")
            print(
                f"Expected fingerprint : SHA256:{known_hosts[target_host][selected_level]}"
            )
            print(f"Received fingerprint : SHA256:{fingerprint}")
            print("=" * 65 + "\n")
            return False

    else:
        if (
            target_host in known_hosts
            and selected_level not in known_hosts[target_host]
        ):
            print(
                f"[*] You have established a connection with '{target_host}' at different level(s) of security before."
            )
            print(f"[*] McEliece key fingerprint is SHA256:{fingerprint}.")
        else:
            # New Host (TOFU - Trust On First Use)
            print(f"[*] The authenticity of host '{target_host}' can't be established.")
            print(f"[*] McEliece key fingerprint is SHA256:{fingerprint}.")
        while True:
            ans = (
                input("Are you sure you want to continue connecting (yes/no)? ")
                .lower()
                .strip()
            )
            if ans in ["yes", "y"]:
                with open(known_pairs_path, "a") as f:
                    f.write(f"{target_host} {selected_level} {fingerprint}\n")
                print(
                    f"[+] Permanently added '{target_host}' to the list of known pairs."
                )
                return True
            elif ans in ["no", "n"]:
                return False
            else:
                print("Please type 'yes' or 'no'.")
