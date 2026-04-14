"""
client.py — Interactive CLI chat client.
Dev 1 — feature/dev1-core-network
No security — pure network layer only.
"""

import socket
import sys
import threading

import colorama

import config
import crypto_sym

colorama.init(autoreset=True)


# ---------------------------------------------------------------------------
# Receive thread
# ---------------------------------------------------------------------------
def receive_loop(sock: socket.socket, color: str, crypto_key: bytes) -> None:
    """Continuously read messages from the server and print them."""
    reset = colorama.Style.RESET_ALL
    buffer = b""
    while True:
        try:
            line, buffer = recv_line(sock, buffer)
            if not line:
                continue
            try:
                decrypted = crypto_sym.decrypt_message(line, crypto_key)
            except ValueError:
                continue
            print(f"\r{decrypted}\n> ", end="", flush=True)
        except OSError:
            return


def recv_line(sock: socket.socket, buffer: bytes) -> tuple[str, bytes]:
    """Read one line from a socket while preserving extra buffered bytes."""
    while b"\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("Socket closed")
        buffer += chunk

    raw_line, buffer = buffer.split(b"\n", 1)
    return raw_line.decode("utf-8", errors="replace").strip(), buffer


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
    buffer = b""
    prompt, buffer = recv_line(sock, buffer)
    print(prompt)

    username = input("> ").strip()
    sock.sendall((username + "\n").encode("utf-8"))

    # --- Authentication handshake (plain transport) ---
    authenticated = False
    while not authenticated:
        server_line, buffer = recv_line(sock, buffer)
        print(server_line)

        lower_line = server_line.lower()
        if "auth mode?" in lower_line:
            mode = input("> ").strip().lower()
            sock.sendall((mode + "\n").encode("utf-8"))
        elif lower_line.startswith("password:"):
            password = input("> ").strip()
            sock.sendall((password + "\n").encode("utf-8"))
        elif lower_line.startswith("confirm password:"):
            confirmation = input("> ").strip()
            sock.sendall((confirmation + "\n").encode("utf-8"))
        elif "login successful" in lower_line or "account created" in lower_line:
            authenticated = True
        elif "goodbye" in lower_line:
            colorama.deinit()
            sock.close()
            print("\n[client] Disconnected.")
            return

    # --- Secret input + key derivation ---
    key_prompt, buffer = recv_line(sock, buffer)
    print(key_prompt)
    secret = input("> ").strip()
    sock.sendall((secret + "\n").encode("utf-8"))

    try:
        crypto_key = crypto_sym.get_or_create_client_key(username=username, secret=secret)
    except ValueError as exc:
        print(f"[error] {exc}")
        colorama.deinit()
        sock.close()
        return

    # --- Welcome message + COLOR_INDEX (encrypted) ---
    encrypted_welcome, buffer = recv_line(sock, buffer)
    try:
        welcome = crypto_sym.decrypt_message(encrypted_welcome, crypto_key)
    except ValueError:
        print("[error] Failed to decrypt server welcome message")
        colorama.deinit()
        sock.close()
        return

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
    t = threading.Thread(target=receive_loop, args=(sock, color, crypto_key), daemon=True)
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
            encrypted_line = crypto_sym.encrypt_message(line, crypto_key)
            if line == "/quit":
                sock.sendall((encrypted_line + "\n").encode("utf-8"))
                break
            sock.sendall((encrypted_line + "\n").encode("utf-8"))
    except KeyboardInterrupt:
        pass
    finally:
        colorama.deinit()
        sock.close()
        print("\n[client] Disconnected.")


if __name__ == "__main__":
    main()
