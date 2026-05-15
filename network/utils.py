"""
Network Utilities for reliable TCP streaming.
Implements Length-Prefixed Framing (4-byte headers).
"""

import struct


def send_msg(sock, msg: bytes) -> None:
    """Add 4-byte size info at the start"""
    # '>I' : Big-endian unsigned int (4 bytes)
    msg_length = struct.pack(">I", len(msg))
    sock.sendall(msg_length + msg)


def recv_msg(sock) -> bytes:
    """Read the 4-byte size header first, then read the message."""
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return b""

    msglen = struct.unpack(">I", raw_msglen)[0]
    return recvall(sock, msglen)


def recvall(sock, n: int) -> bytes:
    """Keep reading until we get exact "n" bytes from the TCP connection."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            if len(data) == 0:
                return b""
            else:
                raise ConnectionError(
                    f"ConnectionError: Excepted size: {n} bytes, recieved {len(data)} bytes."
                )
        data.extend(packet)
    return bytes(data)
