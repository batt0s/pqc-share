"""
Classic McEliece Core Subroutines
Contains internal mathematical operations and PRNG/Hash utilities.
"""

import hashlib
from typing import List, Optional, Tuple

from sage.all import GF, Matrix, vector
from sage.rings.polynomial.polynomial_element import Polynomial
from sage.rings.polynomial.polynomial_ring import PolynomialRing_general
from sage.structure.element import FieldElement

from core.parameters import McElieceParams


def expand_seed(seed: bytes, length_in_bits: int) -> List[int]:
    """
    Symmetric-crypto PRNG: Expands a seed using SHAKE256(64, seed)
    to generate the required number of bits.
    """
    # Spec: Prefix the seed with byte 64 (0x40)
    prefix = bytes([64])
    shake = hashlib.shake_256(prefix + seed)

    length_in_bytes = (length_in_bits + 7) // 8
    random_bytes = shake.digest(length_in_bytes)

    # Convert bytes to a list of bits (little-endian representation)
    bits = []
    for b in random_bytes:
        for i in range(8):
            bits.append((b >> i) & 1)

    return bits[:length_in_bits]


def matgen(
    params: McElieceParams, g: Polynomial, alphas: Tuple[FieldElement, ...]
) -> Optional[Matrix]:
    """
    Algorithm 4.2: Matrix generation for Goppa codes (Systematic form).
    Optimized to compute polynomial evaluations outside the inner loop.
    """
    inv_g_evals = []
    for j in range(params.n):
        eval_val = params.F_q(g(alphas[j]))
        inv_g_evals.append(~eval_val)

    current_alphas = [params.F_q(1) for _ in range(params.n)]

    H_tilde_elements = []
    for i in range(params.t):
        row = []
        for j in range(params.n):
            # h_{i,j} = (alpha_j^i) * (1 / g(alpha_j))
            val = current_alphas[j] * inv_g_evals[j]
            row.append(val)

            current_alphas[j] *= alphas[j]

        H_tilde_elements.append(row)

    H_hat_elements = []
    for i in range(params.t):
        m_rows = [[] for _ in range(params.m)]
        for j in range(params.n):
            poly_list = H_tilde_elements[i][j].polynomial().list()
            coeffs = poly_list + [GF(2)(0)] * (params.m - len(poly_list))
            for k in range(params.m):
                m_rows[k].append(coeffs[k])
        H_hat_elements.extend(m_rows)

    H_hat = Matrix(GF(2), params.m * params.t, params.n, H_hat_elements)
    H_hat.echelonize()

    expected_pivots = tuple(range(params.m * params.t))
    if H_hat.pivots() == expected_pivots:
        T = H_hat.matrix_from_columns(range(params.m * params.t, params.n))
        return T

    return None


def bits_to_bytes(bit_list: List[int]) -> bytes:
    """
    Spec Section 6.2: Representation of objects as byte strings.
    Pads bits to a multiple of 8 and converts to little-endian bytes.
    """
    padded_len = (len(bit_list) + 7) // 8 * 8
    padded_bits = bit_list + [0] * (padded_len - len(bit_list))

    byte_array = bytearray()
    for i in range(0, len(padded_bits), 8):
        byte_val = sum(padded_bits[i + j] << j for j in range(8))
        byte_array.append(byte_val)
    return bytes(byte_array)


def kem_hash(prefix: int, e: List[int], C: List[int]) -> bytes:
    """
    Generates the Session Key K = H(prefix, e, C) using SHAKE256.
    Prefix is 1 for Encapsulation, 0 or 1 for Decapsulation.
    """
    e_bytes = bits_to_bytes(e)
    C_bytes = bits_to_bytes(C)

    shake = hashlib.shake_256()
    shake.update(bytes([prefix]))
    shake.update(e_bytes)
    shake.update(C_bytes)

    # K is a 256-bit (32 byte) session key
    return shake.digest(32)


def encode(params: McElieceParams, e_bits: List[int], T: Matrix) -> List[int]:
    """
    Algorithm 4.3: C = He where H = (I_mt | T).
    """
    # Instead of building the massive H matrix directly,
    # we can compute this very efficiently via block multiplication.
    # C = I_mt * e_left + T * e_right
    mt = params.m * params.t

    e_left = vector(GF(2), e_bits[:mt])
    e_right = vector(GF(2), e_bits[mt:])

    # Matrix multiplication in SageMath
    C_vec = e_left + (T * e_right)
    return list(C_vec)


def split_poly(
    p: Polynomial, ring: PolynomialRing_general
) -> Tuple[Polynomial, Polynomial]:
    """
    Factors the polynomial into even-degree (p0) and odd-degree (p1) terms.
    Applies the rule p(z) = p0²(z) + z * p1²(z).
    In fields of characteristic 2, every element has a unique square root (sqrt).
    Taken from Risse's paper.
    """
    coeffs = p.list()
    p0_coeffs = [c.sqrt() for c in coeffs[0::2]]
    p1_coeffs = [c.sqrt() for c in coeffs[1::2]]
    return ring(p0_coeffs), ring(p1_coeffs)


def decode(
    params: McElieceParams, C: List[int], private_key: dict
) -> Optional[List[int]]:
    """
    Algorithm 4.4: Decodes C to a word e of Hamming weight t.
    Implements Patterson's Algorithm using algebraic methods from Thomas Risse.
    """
    g = params.R_y(private_key["g"])
    alphas = private_key["alpha"]

    # STEP 1: Turn the syndrom vector (C) to a polynomial (S_y)
    v = [int(x) for x in C] + [0] * (params.n - len(C))

    S_y = params.R_y(0)
    for j in range(params.n):
        if v[j] == 1:
            term = (params.y - alphas[j]).inverse_mod(g)
            S_y = (S_y + term) % g

    if S_y == 0:
        return None

    # STEP 2: Start Patterson - calculate w(z) (w^2 = z mod g)
    g0, g1 = split_poly(g, params.R_y)
    try:
        g1_inv = g1.inverse_mod(g)
    except (ZeroDivisionError, ValueError):
        return None
    w = (g0 * g1_inv) % g

    # STEP 3: Compute T(z) and R(z)
    try:
        T = S_y.inverse_mod(g)
    except (ZeroDivisionError, ValueError):
        return None

    T_plus_z = (T + params.y) % g
    T0, T1 = split_poly(T_plus_z, params.R_y)
    R = (T0 + w * T1) % g

    # STEP 4: Extended Euclidean Algorithm (Half-GCD)
    # a(z) = b(z)*R(z) mod g(z) s.t. deg(a) <= t/2
    a_prev, a_curr = g, R
    b_prev, b_curr = params.R_y(0), params.R_y(1)

    while a_curr.degree() > params.t // 2:
        q, r = a_prev.quo_rem(a_curr)
        a_prev = a_curr
        a_curr = r

        b_next = b_prev + q * b_curr
        b_prev = b_curr
        b_curr = b_next

    a, b = a_curr, b_curr

    # STEP 5: Calculate Error Locator Polynomial
    # sigma(z) = a^2(z) + z * b^2(z)
    sigma = a**2 + params.y * b**2

    # STEP 6: Chien Search (Finding Roots)
    # Roots of the error polynomial shows us where are the errors
    e = [0] * params.n
    error_count = 0

    for i in range(params.n):
        # If locator (alpha), is a root of sigma, there is an error at that index
        if sigma(alphas[i]) == 0:
            e[i] = 1
            error_count += 1

    # Check the number of errors
    if error_count == params.t:
        return e

    return None
