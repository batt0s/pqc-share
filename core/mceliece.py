"""Classic McEliece Core Algorithms (Spec Section 5)"""

import os
from typing import List, Optional, Tuple

from sage.all import Matrix
from sage.rings.polynomial.polynomial_element import Polynomial
from sage.structure.element import FieldElement

from core.parameters import McEliece348864
from core.subroutines import decode, encode, expand_seed, kem_hash, matgen


def generate_irreducible(
    params: McEliece348864, bits: List[int]
) -> Optional[Polynomial]:
    """
    Algorithm 5.1: Irreducible-polynomial generation.
    Takes a string of sigma_1 * t input bits and outputs a monic irreducible
    degree-t polynomial g in F_q[x], or None (failure).

    Args:
        params: McEliece348864 parameters.
        bits: A list of integers (0 or 1) of length sigma_1 * t.

    Returns:
        A monic irreducible degree-t polynomial g, or None.
    """
    expected_length = params.sigma_1 * params.t
    if len(bits) != expected_length:
        raise ValueError(f"Input bits must be exactly {expected_length} bits long.")

    betas = []

    # Step 1: Define beta_j for each j in {0, 1, ..., t-1}
    for j in range(params.t):
        beta_j = params.F_q(0)
        # Uses only the first m bits of each sigma_1 group
        for i in range(params.m):
            bit_index = params.sigma_1 * j + i
            if bits[bit_index] == 1:
                beta_j += params.F_q.gen() ** i
        betas.append(beta_j)

    # Step 2: Define beta in F_q[y]/F(y)
    # beta = beta_0 + beta_1*y + ... + beta_{t-1}*y^{t-1}
    beta_elem = sum(
        (betas[j] * (params.beta**j) for j in range(params.t)), params.F_qt(0)
    )

    # Step 3: Compute the minimal polynomial g of beta over F_q
    g_raw = beta_elem.minpoly()
    g = params.R_y(g_raw.list())

    # Step 4: Return g if g has degree t. Otherwise return None (bottom).
    if g.degree() == params.t:
        return g

    return None


def generate_field_ordering(
    params: McEliece348864, bits: List[int]
) -> Optional[Tuple[FieldElement, ...]]:
    """
    Algorithm 5.2: Field-ordering generation.
    Takes a string of sigma_2 * q input bits and outputs a sequence of
    q distinct elements of F_q, or None (failure).

    Args:
        params: McEliece348864 parameters.
        bits: A list of integers (0 or 1) of length sigma_2 * q.

    Returns:
        A tuple containing (alpha_0, alpha_1, ..., alpha_{q-1}), or None.
    """
    expected_length = params.sigma_2 * params.q
    if len(bits) != expected_length:
        raise ValueError(f"Input bits must be exactly {expected_length} bits long.")

    a_vals = []

    # Step 1: Group bits into sigma_2-bit integers a_i
    for i in range(params.q):
        a_i = 0
        for j in range(params.sigma_2):
            bit_index = (i * params.sigma_2) + j
            a_i += bits[bit_index] * (1 << j)
        a_vals.append(a_i)

    # Step 2: If a_0, ..., a_{q-1} are not distinct, return None
    if len(set(a_vals)) != params.q:
        return None

    # Step 3: Sort the pairs (a_i, i) in lexicographic order
    # This automatically sorts by the integer value a_i first, keeping track of the original index i.
    pairs = [(a_vals[i], i) for i in range(params.q)]
    pairs.sort()

    # Extract the permutation pi
    pi = [pair[1] for pair in pairs]

    # Step 4: Define alpha_i based on the permutation
    alphas = []
    for i in range(params.q):
        pi_i = pi[i]
        alpha_i = params.F_q(0)

        for j in range(params.m):
            # Extract the j-th least significant bit of pi(i)
            pi_i_j = (pi_i >> j) & 1
            if pi_i_j == 1:
                alpha_i += params.F_q.gen() ** (params.m - 1 - j)

        alphas.append(alpha_i)

    # Step 5: Output (alpha_0, alpha_1, ..., alpha_{q-1})
    return tuple(alphas)


def seeded_keygen(params: McEliece348864, seed: bytes) -> Tuple[Matrix, dict]:
    """
    Algorithm 5.3: SEEDED_KEYGEN subroutine.
    Takes an l-bit seed and outputs a (public_key, private_key) pair.
    """
    current_seed = seed

    # This loop handles the failure conditions specified in steps 4, 5, and 7 .
    while True:
        # Step 1: Compute E = G(delta)
        total_bits = (
            params.n
            + (params.sigma_2 * params.q)
            + (params.sigma_1 * params.t)
            + params.l
        )
        E_bits = expand_seed(current_seed, total_bits)

        # Step 2 & 3: Extract delta' and s
        s_bits = E_bits[: params.n]
        delta_prime_bits = E_bits[-params.l :]
        delta_prime = bytes(
            [
                sum([delta_prime_bits[i * 8 + j] << j for j in range(8)])
                for i in range(params.l // 8)
            ]
        )

        # Slicing the remaining bits for alpha and g
        offset = params.n
        alpha_bits = E_bits[offset : offset + (params.sigma_2 * params.q)]
        offset += params.sigma_2 * params.q
        g_bits = E_bits[offset : offset + (params.sigma_1 * params.t)]

        # Step 4: Compute alphas using FIELD_ORDERING
        alphas = generate_field_ordering(params, alpha_bits)
        if alphas is None:
            current_seed = delta_prime  # Step 4 failure
            continue

        # Step 5: Compute g using IRREDUCIBLE
        g = generate_irreducible(params, g_bits)
        if g is None:
            current_seed = delta_prime  # Step 5 failure
            continue

        # Step 6: Define Gamma (implicit in passing g and alphas to matgen)

        # Step 7: Compute MATGEN
        T = matgen(params, g, alphas)
        if T is None:
            current_seed = delta_prime  # Step 7 failure
            continue

        # Step 8 & 9: Output Public Key (T) and Private Key
        # For systematic sets like mceliece348864, c is empty
        private_key = {"delta": current_seed, "g": g, "alpha": alphas, "s": s_bits}

        return T, private_key


def generate_fixed_weight(params: McEliece348864) -> List[int]:
    """
    Algorithm 5.4: Generates a vector e in F_2^n of exact weight t.
    """
    # Determine tau
    # For mceliece348864: q=4096, n=3488. Since q/2 <= n < q, tau = 2t.
    tau = 2 * params.t if (params.q // 2 <= params.n < params.q) else params.t

    while True:
        # Step 1: Generate sigma_1 * tau random bits
        rand_bytes = os.urandom((params.sigma_1 * tau + 7) // 8)
        b = []
        for byte in rand_bytes:
            for i in range(8):
                b.append((byte >> i) & 1)
        b = b[: params.sigma_1 * tau]

        # Step 2: Define d_j
        d = []
        for j in range(tau):
            d_j = 0
            for i in range(params.m):
                d_j += b[params.sigma_1 * j + i] * (1 << i)
            d.append(d_j)

        # Step 3: Define a_0...a_{t-1} strictly in range [0, n-1]
        a = [val for val in d if val < params.n]
        if len(a) < params.t:
            continue  # Restart

        a = a[: params.t]

        # Step 4: Check if all distinct
        if len(set(a)) != params.t:
            continue  # Restart

        # Step 5: Define weight-t vector e
        e = [0] * params.n
        for index in a:
            e[index] = 1

        return e


def encap(params: McEliece348864, T: Matrix) -> Tuple[List[int], bytes]:
    """
    Algorithm 5.5: Takes public key T, outputs ciphertext C and session key K .
    """
    # Step 1: Generate e of weight t
    e = generate_fixed_weight(params)
    e = [int(x) for x in e]

    # Step 2: Compute C = ENCODE(e, T)
    C = encode(params, e, T)
    C = [int(x) for x in C]

    # Step 3: Compute K = H(1, e, C)
    K = kem_hash(1, e, C)

    # Step 4: Output ciphertext C and session key K
    return C, K


def decap(params: McEliece348864, C: List[int], private_key: dict) -> bytes:
    """
    Algorithm 5.6: Takes ciphertext C and private key, outputs session key K .
    """
    # Step 1: Set b = 1
    b = 1

    # Step 2: Extract s and Gamma' from private key
    s = private_key["s"]

    # Step 3: Compute e = DECODE(C, Gamma')
    e = decode(params, C, private_key)

    # If e = None (decoding failed), set e = s and b = 0
    # Bu adım, Seçilmiş Şifreli Metin Saldırılarına (IND-CCA2) karşı hayati bir önlemdir.
    # Saldırgana "şifre çözülemedi" hatası dönmek yerine, sahte bir anahtar üretip onu yanıltırız.
    if e is None:
        e = s
        b = 0

    # Step 4: Compute K = H(b, e, C)
    K = kem_hash(b, e, C)

    # Step 5: Output session key K
    return K
