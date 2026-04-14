"""
client.py — Interactive CLI chat client.
Dev 1 — feature/dev1-core-network
No security — pure network layer only.
"""

import socket
import sys
import threading
import time
from datetime import datetime

import colorama

import config

colorama.init(autoreset=True)


# ---------------------------------------------------------------------------
# Receive thread
# ---------------------------------------------------------------------------
def receive_loop(sock: socket.socket, color: str) -> None:
    """Continuously read messages from the server and print them."""
    reset = colorama.Style.RESET_ALL
    while True:
        try:
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    print(f"\n{colorama.Fore.RED}[disconnected]{reset}")
                    return
                data += chunk
                if b"\n" in data:
                    break
            for raw_line in data.split(b"\n"):
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                # Colour the username portion if it matches "[HH:MM:SS] user : msg"
                print(f"\r{line}\n> ", end="", flush=True)
        except OSError:
            return


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    # Parse args
    args = sys.argv[1:]
    host = args[0] if len(args) >= 1 else config.DEFAULT_HOST
    port = int(args[1]) if len(args) >= 2 else config.DEFAULT_PORT

    # Connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"[error] Cannot connect to {host}:{port}")
        sys.exit(1)

    # --- Username prompt ---
    # First read the server's "Enter your username:" prompt
    buf = b""
    while b"\n" not in buf:
        buf += sock.recv(4096)
    prompt = buf.decode("utf-8", errors="replace").strip()
    print(prompt)

    username = input("> ").strip()
    sock.sendall((username + "\n").encode("utf-8"))

    # --- Welcome message + COLOR_INDEX ---
    buf = b""
    while b"\n" not in buf:
        buf += sock.recv(4096)
    welcome = buf.decode("utf-8", errors="replace").strip()

    color_index = hash(username) % len(config.COLORS)  # fallback
    # Try to parse COLOR_INDEX from server welcome
    for part in welcome.split():
        if part.startswith("COLOR_INDEX:"):
            try:
                color_index = int(part.split(":")[1])
            except ValueError:
                pass

    color = config.COLORS[color_index]
    reset = colorama.Style.RESET_ALL
    print(f"{color}{welcome}{reset}")

    # --- Start receive thread ---
    t = threading.Thread(target=receive_loop, args=(sock, color), daemon=True)
    t.start()

    # --- Send loop ---
    try:
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                break
            if not line:
                continue
            if line == "/quit":
                sock.sendall(b"/quit\n")
                break
            sock.sendall((line + "\n").encode("utf-8"))
    except KeyboardInterrupt:
        pass
    finally:
        colorama.deinit()
        sock.close()
        print("\n[client] Disconnected.")


if __name__ == "__main__":
    main()
