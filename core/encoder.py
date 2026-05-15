"""
PQC Key Encoder Module
Turn SageMath GF(2) matrices and algebraic objects to pure byte arrays.
"""

import base64
import json

from sage.all import GF, Matrix


def export_public_key(T_matrix, params) -> bytes:
    """
    Turn GF(2) Matrices to bytes by concatting bits.
    And Export OpenSSL/SSH-like PEM format.
    """
    # Turn the matrix into a list
    bits = [int(x) for x in T_matrix.list()]

    # Group them into packages in size of 8 bits (1 byte)
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i : i + 8]
        # Binary to int (bit shifting)
        val = sum(bit << (7 - j) for j, bit in enumerate(chunk))
        byte_array.append(val)

    # Turn bytes to Base64 string
    b64 = base64.b64encode(byte_array).decode("utf-8")

    # Standart PEM format: add new line after 64 chars
    b64_lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]

    pem = "-----BEGIN McEliece PUBLIC KEY-----\n"
    pem += "\n".join(b64_lines)
    pem += "\n-----END McEliece PUBLIC KEY-----\n"

    return pem.encode("utf-8")


def import_public_key(pem_bytes: bytes, params):
    """
    Takes bytes (PEM Format) and turn them into GF(2) matrices.
    """
    pem_str = pem_bytes.decode("utf-8").strip()
    lines = pem_str.split("\n")

    # Remove headers
    b64 = "".join([l for l in lines if not l.startswith("-")])
    byte_array = base64.b64decode(b64)

    # Turn bytes into bits
    bits = []
    for b in byte_array:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    # Remove padding bits and get the exact matrix size
    expected_size = (params.m * params.t) * params.k
    bits = bits[:expected_size]

    # Create the matrix
    return Matrix(GF(2), params.m * params.t, params.k, bits)


def export_private_key(private_key_dict: dict) -> bytes:
    """
    Private Key Dictionary to PEM bytes.
    Serialize g (polynomial), alpha (list) ve s (bytes).
    """

    def elem_to_int(elem):
        return sum(int(bit) << i for i, bit in enumerate(elem.polynomial().list()))

    # Turn coefficents of polynomial g and alphas into integers
    data = {
        "g": [elem_to_int(c) for c in private_key_dict["g"].list()],
        "alpha": [elem_to_int(a) for a in private_key_dict["alpha"]],
        "s": [int(bit) for bit in private_key_dict["s"]],
    }

    # Package them into a JSON string and to Base64
    json_bytes = json.dumps(data).encode("utf-8")
    b64 = base64.b64encode(json_bytes).decode("utf-8")
    b64_lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]

    pem = "-----BEGIN McEliece PRIVATE KEY-----\n"
    pem += "\n".join(b64_lines)
    pem += "\n-----END McEliece PRIVATE KEY-----\n"
    return pem.encode("utf-8")


def import_private_key(pem_bytes: bytes, params):
    """PEM bytes to SageMath Private Key Dictionary"""
    pem_str = pem_bytes.decode("utf-8").strip()
    lines = pem_str.split("\n")
    b64 = "".join([l for l in lines if not l.startswith("-")])

    json_bytes = base64.b64decode(b64)
    data = json.loads(json_bytes.decode("utf-8"))

    def int_to_elem(val, field):
        a = field.gen()  # generator of field
        res = field(0)  # start with 0
        i = 0
        while val > 0:
            if val & 1:  # if the bit at the end is 1
                res += a**i  # add a^i
            val >>= 1  # next bit (shift right)
            i += 1
        return res

    g_coeffs = [int_to_elem(c, params.F_q) for c in data["g"]]
    g = params.R_y(g_coeffs)

    alphas = tuple(int_to_elem(a, params.F_q) for a in data["alpha"])
    s = [GF(2)(bit) for bit in data["s"]]

    return {"g": g, "alpha": alphas, "s": s}


def export_ciphertext(C_list: list) -> bytes:
    """
    Takes the C capsule (a list of 0s and 1s of length 768 bits),
    exports as 96 bytes PEM formatted packed byte array.
    """
    bits = [int(x) for x in C_list]

    # Group as 1 byte packets
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i : i + 8]
        val = sum(bit << (7 - j) for j, bit in enumerate(chunk))
        byte_array.append(val)

    b64 = base64.b64encode(byte_array).decode("utf-8")
    b64_lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]

    pem = "-----BEGIN McEliece CIPHERTEXT-----\n"
    pem += "\n".join(b64_lines)
    pem += "\n-----END McEliece CIPHERTEXT-----\n"

    return pem.encode("utf-8")


def import_ciphertext(pem_bytes: bytes, params) -> list:
    """
    Takes the PEM-formatted data and turns into a list.
    """
    pem_str = pem_bytes.decode("utf-8").strip()
    lines = pem_str.split("\n")

    # Remove headers
    b64 = "".join([l for l in lines if not l.startswith("-")])
    byte_array = base64.b64decode(b64)

    # Bytes to Bits
    bits = []
    for b in byte_array:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    # Remove padding
    expected_size = params.n - params.k
    return bits[:expected_size]
