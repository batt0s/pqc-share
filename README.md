# PQC-Share

**Quantum-safe peer-to-peer file transfer using Classic McEliece KEM + AES-256-GCM.**

PQC-Share lets two machines exchange files over a TCP connection with end-to-end encryption that is resistant to attacks from future quantum computers. Key encapsulation is handled by [Classic McEliece](https://classic.mceliece.org/) — one of the NIST PQC standardisation finalists — and the actual file data is encrypted with AES-256-GCM.

>IMPORTANT NOTICE: This is a student project developed for academic and educational purposes. It should not be used for real-world data security.

---

## Table of Contents

- [Why Post-Quantum?](#why-post-quantum)
- [Features](#features)
- [Architecture Overview](#architecture-overview)
  - [Protocol Flow](#protocol-flow)
  - [Module Map](#module-map)
  - [McEliece KEM Internals](#mceliece-kem-internals)
- [Security Properties](#security-properties)
- [Installation](#installation)
- [Usage](#usage)
  - [Receiver (listen mode)](#receiver-listen-mode)
  - [Sender (send mode)](#sender-send-mode)
  - [NIST Security Levels](#nist-security-levels)
  - [Alias Configuration](#alias-configuration)
- [Running the Tests](#running-the-tests)
- [Known Limitations and Future Work](#known-limitations-and-future-work)
- [Bibliography](#bibliography)

---

## Why Post-Quantum?

Classical public-key algorithms (RSA, ECDH, ECDSA) derive their security from the hardness of integer factorisation or the discrete logarithm problem. Shor's algorithm, running on a sufficiently large quantum computer, solves both in polynomial time, rendering these schemes broken.

McEliece's public-key cryptosystem (1978) is based on the hardness of decoding a random linear code — a problem for which no efficient quantum algorithm is known. NIST selected a variant of this scheme (Classic McEliece) as a KEM standard in its post-quantum cryptography standardisation process.

---

## Features

- **Classic McEliece KEM** — key encapsulation using binary Goppa codes
- **Three NIST security levels** — `mceliece348864` (L1), `mceliece460896` (L3), `mceliece6688128` (L5)
- **AES-256-GCM file encryption** — authenticated, streaming, memory-efficient chunked I/O
- **TOFU host verification** — SSH-style fingerprint pinning to detect MITM attacks
- **Passphrase-protected private keys** — PBKDF2-HMAC-SHA256 + AES-GCM key wrapping
- **IND-CCA2 hardened decapsulation** — returns a pseudorandom key on failure rather than an error signal
- **Length-prefixed TCP framing** — reliable streaming over raw TCP

---

## Architecture Overview

### Protocol Flow

```
  RECEIVER (Bob)                              SENDER (Alice)
  ──────────────                              ──────────────
  Load / generate key pair
  Start TCP listener
                          ←── TCP connect ───
  Send Public Key (PEM)   ───────────────────→
                                              Verify fingerprint (TOFU)
                                              Encapsulate: C, K = ENCAP(pk)
                          ←── Capsule (C) ────
  Decapsulate: K = DECAP(C, sk)
  ── both sides now share K ──────────────────────────────────
                                              Encrypt file with AES-256-GCM(K)
                          ←── Encrypted file (chunks) ───────
  Decrypt & verify tag
  Save plaintext file
```

Both sides derive the **same 256-bit session key K** from the KEM exchange. The key never travels over the wire.

---

### Module Map

```
pqc-share/
├── cli.py                  Entry point; argument parsing
├── core/
│   ├── parameters.py       McEliece parameter sets (NIST L1/L3/L5)
│   ├── mceliece.py         KEM algorithms: KEYGEN, ENCAP, DECAP (Spec §5)
│   ├── subroutines.py      Math primitives: MATGEN, ENCODE, DECODE (Patterson), EXPAND_SEED, KEM_HASH
│   ├── encoder.py          Serialisation: GF(2) matrices ↔ PEM bytes, ciphertext packing
│   ├── key_manager.py      Key persistence: load or generate, passphrase prompting
│   └── config.py           SSH-style alias config (~/.pqc_share/config)
├── crypto/
│   └── cipher.py           AES-256-GCM file encryption / decryption (chunked)
├── network/
│   ├── client.py           Sender logic (connect, send public key request, stream file)
│   ├── server.py           Receiver logic (listen, key exchange, receive & decrypt file)
│   ├── security.py         TOFU fingerprint verification (~/.pqc_share/known_pairs)
│   └── utils.py            Length-prefixed TCP framing (send_msg / recv_msg)
└── tests/
    ├── test_kem.py          KEM unit tests (keygen dimensions, encap/decap round-trip)
    ├── test_cipher.py       AES-GCM unit tests (encrypt/decrypt, tamper detection)
    └── test_network.py      TCP framing unit tests (send/recv, EOF, incomplete reads)
```

---

### McEliece KEM Internals

Classic McEliece is a **code-based** KEM. Security rests on two hard problems:

1. **Goppa code indistinguishability** — a random-looking parity-check matrix hides the underlying Goppa code structure.
2. **Syndrome decoding** — recovering an error vector from a syndrome is NP-hard in general.

#### Key Generation (`seeded_keygen` — Spec 5.3)

A 256-bit seed $\delta$ is expanded with SHAKE-256 into:
- a **field ordering** $\alpha_0, \ldots, \alpha_{q-1}$ — a permutation of $F_q$
- an **irreducible polynomial** $g \in F_q[y]$ of degree `t` — defines the Goppa code
- a **noise string** $s \in F_2^n$ — used as a decoy in decapsulation failures

`MATGEN` builds the $$(mt \times n)$$ parity-check matrix `H` in systematic form $$[I | T]$$. The public key is `T`; the private key is $$(\delta, g, \alpha, s)$$.

#### Encapsulation (`encap` — Spec 5.5)

1. Sample a random weight-`t` error vector $e \in F_2^n$.
2. Compute the syndrome: $C = He \mod 2$ (implemented efficiently as $e_{\text{left}} + T·e_{\text{right}}$).
3. Derive the session key: $K = \text{SHAKE-256}(1 \| e \| C)$.

#### Decapsulation (`decap` — Spec 5.6)

1. Run **Patterson's algorithm** on $(C, g, \alpha)$ to recover `e`.
2. If decoding fails, substitute the private noise string $s$ and set a failure flag $b = 0$.
3. Derive $K = \text{SHAKE-256}(b \| e \| C)$.

Substituting $s$ on failure (rather than returning an error) is the IND-CCA2 countermeasure: an adversary probing with malformed ciphertexts cannot distinguish a decryption failure from a successful decryption.

#### Patterson's Algorithm (inside `decode`)

Patterson's algorithm corrects up to $t$ errors in a binary Goppa code in polynomial time:

1. Build the **syndrome polynomial** $S(y) = \sum \frac{1}{y - \alpha_j} \mod g$ for each set bit in $C$.
2. Compute $w$ such that $w² ≡ y mod g$ (exists and is unique in characteristic 2).
3. Compute $T = S^{-1} \mod g$, then factor $T(y) + y = a^2(y) + y·b^2(y)$ using square-root splitting.
4. Run the **half-GCD** (extended Euclidean) to find polynomials $a, b$ with $deg(a) \le t/2$.
5. Form the **error locator polynomial** $\sigma(y) = a^2(y) + y·b^2(y)$.
6. **Chien search**: evaluate $\sigma(α_i)$ for each $i$; a root at $\alpha_i$ means position $i$ is in error.

---

## Security Properties

| Property | Mechanism |
|---|---|
| Quantum resistance | McEliece KEM — no known quantum speedup for syndrome decoding |
| Forward secrecy | Fresh `e` sampled per session; compromise of long-term key does not expose past sessions |
| IND-CCA2 | Decapsulation failure returns pseudorandom key, not an error |
| Data confidentiality | AES-256-GCM authenticated encryption |
| Data integrity | GCM authentication tag; any bit flip raises `InvalidTag` before plaintext is used |
| Key confidentiality | Private key encrypted with PBKDF2 + AES-GCM; passphrase never stored |
| Host authentication | TOFU fingerprint pinning; MITM key substitution raises a prominent warning |

> **Note:** TOFU provides only first-use authentication. For stronger guarantees, a PKI or out-of-band fingerprint verification should be used.

---

## Installation

### Requirements

- Python 3.11+
- [SageMath](https://www.sagemath.org/) 10.x (provides the `sage` Python package)
- `cryptography` and `tqdm` (pip-installable)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/your-username/pqc-share.git
cd pqc-share

# 2. Install SageMath
#    macOS (Homebrew):   brew install sagemath
#    Ubuntu/Debian:      sudo apt install sagemath
#    conda:              conda install -c conda-forge sagemath

# 3. Install Python dependencies inside the SageMath environment
pip install cryptography tqdm

# 4. Verify
sage -python cli.py --help
```

---

## Usage

### Receiver (listen mode)

```bash
# Listen on the default port (65432), save the file as "secret.pdf"
sage -python cli.py listen -o secret.pdf

# Listen on a custom port
sage -python cli.py listen -p 9000 -o output.dat
```

On first run the receiver generates a key pair and stores it in `~/.pqc_share/keys/`. You will be prompted for a passphrase to protect the private key.

### Sender (send mode)

```bash
# Send a file to a receiver at 192.168.1.42
sage -python cli.py send -t 192.168.1.42 -f document.pdf

# Custom port
sage -python cli.py send -t 192.168.1.42 -p 9000 -f document.pdf
```

On first connection to a host you will be shown the receiver's public key fingerprint and asked to confirm — exactly like SSH.

### NIST Security Levels

Both sides **must** use the same `--level` flag:

| Flag | Parameter Set | Classical Security | Public Key Size |
|---|---|---|---|
| `--level 1` (default) | `mceliece348864` | ~128-bit | ~261 KB |
| `--level 3` | `mceliece460896` | ~192-bit | ~524 KB |
| `--level 5` | `mceliece6688128` | ~256-bit | ~1044 KB |

```bash
# Receiver
sage -python cli.py --level 3 listen -o file.dat

# Sender
sage -python cli.py --level 3 send -t 192.168.1.42 -f file.dat
```

### Alias Configuration

You can create `~/.pqc_share/config` to avoid typing IPs repeatedly:

```
Host alice
    Hostname 192.168.1.42
    Port     9000

Host bob-laptop
    Hostname 10.0.0.5
```

Then use the alias:

```bash
sage -python cli.py send -t alice -f document.pdf
```

---

## Running the Tests

```bash
# Install test dependencies
pip install pytest

# Run all tests
pytest tests/ -v

# Run a specific test suite
pytest tests/test_cipher.py -v
pytest tests/test_network.py -v
pytest tests/test_kem.py -v  # Note: slow due to key generation
```

The KEM tests are slow at L1 (~30–120 seconds depending on hardware) because key generation runs the full McEliece keygen. CI runs are expected to take several minutes.

---

## Known Limitations and Future Work

- **No streaming integrity** — AES-GCM authenticates the whole file at the end. Partial plaintext may be written to disk before the tag is verified. A chunked AEAD scheme (e.g. per-chunk nonces + tags) would fix this.
- **Single connection** — the server exits after one successful transfer.
- **TOFU only** — no PKI; fingerprints must be verified out-of-band for strong guarantees. I'm thinking of a Ed25519-based signature scheme.
- **SageMath dependency** — SageMath is a large runtime (~1 GB). A pure-Python or C-extension implementation of the GF(2^m) arithmetic would make distribution much easier. I'm thinking of a Rust-extension implementation.
- **Performance** — key generation at L5 can take several minutes in pure Python/SageMath. This is a known trade-off with McEliece compared to lattice-based KEMs.

---

## Bibliography

1. **McEliece, R. J.** (1978). *A Public-Key Cryptosystem Based on Algebraic Coding Theory*. DSN Progress Report 42-44, Jet Propulsion Laboratory. — The original McEliece proposal.

2. **Classic McEliece Team** (2022). *Classic McEliece: conservative code-based cryptography — Algorithm Specification and Supporting Documentation* (v2022.10.22). [https://classic.mceliece.org/mceliece-spec-20221023.pdf](https://classic.mceliece.org/mceliece-spec-20221023.pdf) — NIST submission specification; primary reference for all algorithm numbering in this codebase.

3. **Patterson, N. J.** (1975). *The Algebraic Decoding of Goppa Codes*. IEEE Transactions on Information Theory, 21(2), 203–207. — The decoding algorithm implemented in `core/subroutines.py::decode`.

4. **Risse, T.** (2006). *On Decoding Goppa Codes*. Fachhochschule Frankfurt am Main. — Practical exposition of Patterson's algorithm with the square-root splitting trick (`split_poly`) used here.

5. **Goppa, V. D.** (1970). *A New Class of Linear Error-Correcting Codes*. Problemy Peredachi Informatsii, 6(3), 24–30. — Original definition of Goppa codes.

6. **Berlekamp, E. R., McEliece, R. J., & van Tilborg, H. C. A.** (1978). *On the Inherent Intractability of Certain Coding Problems*. IEEE Transactions on Information Theory, 24(3), 384–386. — NP-hardness of general syndrome decoding; the security foundation.

7. **McGrew, D. A., & Viega, J.** (2004). *The Security and Performance of the Galois/Counter Mode (GCM) of Operation*. INDOCRYPT 2004, LNCS 3348, pp. 343–355. — AES-GCM, used in `crypto/cipher.py`.
