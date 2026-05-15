"""Unit Tests for TCP Network Utilities"""

import socket

import pytest

from network.utils import recv_msg, send_msg


class TestNetworkUtils:
    @pytest.fixture
    def connected_sockets(self):
        """
        Create a socket pair (Alice and Bob) for testing.
        """
        alice_sock, bob_sock = socket.socketpair()
        yield alice_sock, bob_sock
        alice_sock.close()
        bob_sock.close()

    def test_send_and_recv_msg(self, connected_sockets):
        alice, bob = connected_sockets
        test_payload = b"This is a test message for PQC-Share." * 1000

        # Alice sends
        send_msg(alice, test_payload)

        # Bob recieves
        received_payload = recv_msg(bob)

        assert received_payload == test_payload
        assert type(received_payload) is bytes

    def test_empty_message_graceful_close(self, connected_sockets):
        alice, bob = connected_sockets

        # EOF (Dosya sonu)
        send_msg(alice, b"")

        received_payload = recv_msg(bob)
        assert received_payload == b""

    def test_connection_error_on_incomplete_read(self, connected_sockets):
        alice, bob = connected_sockets

        # Alice sends a header promising a 100 byte message
        import struct

        fake_header = struct.pack(">I", 100)
        alice.sendall(fake_header)

        # But sends only 10 bytes and closes the connection
        alice.sendall(b"x" * 10)
        alice.close()

        # Bob mesajı okumaya çalıştığında ConnectionError patlamalıdır!
        # Bob needs to see a ConnectionError
        with pytest.raises(ConnectionError):
            recv_msg(bob)
