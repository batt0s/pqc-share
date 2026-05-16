"""
PQC-Share: Quantum Safe P2P File Sharing Tool
Main Command Line Interface
"""

import argparse
import os
import sys

from core import parameters
from core.config import resolve_target
from network.client import send_file
from network.server import start_server


def main():
    # Main Parser
    parser = argparse.ArgumentParser(
        description="PQC-Share: Quantum Safe P2P File Sharing Tool.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Commands (listen and send)
    subparsers = parser.add_subparsers(dest="command", help="Available Commands")
    subparsers.required = True

    # LISTEN Commands
    listen_parser = subparsers.add_parser(
        "listen", help="Listen incoming file transfer requests."
    )
    listen_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=65432,
        help="The PORT to listen to (Default: 65432)",
    )
    listen_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="recieved.dat",
        help="Where to write the recieved file (Default: recieved.dat)",
    )

    # SEND Commands
    send_parser = subparsers.add_parser("send", help="Send a file to an adress.")
    send_parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        help="Target IP address (Ex: 192.168.1.5)",
    )
    send_parser.add_argument(
        "-p", "--port", type=int, default=65432, help="The target PORT (Default: 65432)"
    )
    send_parser.add_argument(
        "-f", "--file", type=str, required=True, help="The path of the file to send to."
    )

    parser.add_argument(
        "--level",
        type=int,
        choices=[1, 3, 5],
        default=1,
        help="NIST Security Level (1: AES-128, 3: AES-192, 5: AES-256) (Default: 1)\nBoth sides must use the same level!",
    )

    args = parser.parse_args()

    params = parameters.McElieceParams(level=args.level)
    print(f"[*] Using NIST Level {args.level}")
    print("[!] Warning: Both sides must use the same level!")

    # CLI
    if args.command == "listen":
        print("=== PQC-Share Reciever Mode ===")
        start_server(
            params, host="0.0.0.0", port=args.port, output_filename=args.output
        )

    elif args.command == "send":
        if not os.path.exists(args.file):
            print(f"[-] ERROR: File could not found: '{args.file}'!")
            sys.exit(1)

        print("=== PQC-Share Sender Mode ===")
        target_ip, target_port = resolve_target(args.target, args.port)
        send_file(params, target_ip, target_port, args.file)


if __name__ == "__main__":
    main()
