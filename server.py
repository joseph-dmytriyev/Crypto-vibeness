"""
server.py — Multi-client TCP chat server with rooms.
Dev 1 — feature/dev1-core-network
No security — pure network layer only.
"""

import asyncio
import logging
import os
import sys
from datetime import datetime

import config

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
os.makedirs("logs", exist_ok=True)
log_filename = f"logs/log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------
clients: dict[str, "ClientSession"] = {}   # username -> ClientSession
rooms: dict[str, dict] = {
    config.DEFAULT_ROOM: {"password": None, "members": set()}
}


# ---------------------------------------------------------------------------
# ClientSession
# ---------------------------------------------------------------------------
class ClientSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.username: str = ""
        self.room: str = config.DEFAULT_ROOM
        self.color_index: int = 0

    async def send(self, message: str) -> None:
        """Send a UTF-8 line to this client."""
        try:
            self.writer.write((message + "\n").encode("utf-8"))
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    async def readline(self) -> str:
        """Read one line from the client (strips \\r\\n)."""
        data = await self.reader.readuntil(b"\n")
        return data.decode("utf-8", errors="replace").strip()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def broadcast_room(room_name: str, message: str, exclude: str = "") -> None:
    """Send message to all members of a room except the excluded username."""
    for username, session in list(clients.items()):
        if username != exclude and session.room == room_name:
            await session.send(message)


async def handle_command(session: ClientSession, line: str) -> None:
    """Process a slash command from a client."""
    parts = line.split()
    cmd = parts[0].lower()

    if cmd == "/list":
        room_list = []
        for name, info in rooms.items():
            lock = " [locked]" if info["password"] else ""
            room_list.append(f"  {name}{lock}")
        await session.send("Rooms:\n" + "\n".join(room_list))

    elif cmd == "/create":
        if len(parts) < 2:
            await session.send("Usage: /create <room> [password]")
            return
        room_name = parts[1]
        password = parts[2] if len(parts) >= 3 else None
        if room_name in rooms:
            await session.send(f"Room '{room_name}' already exists.")
            return
        rooms[room_name] = {"password": password, "members": set()}
        logger.info(f"CREATE {room_name} by {session.username}")
        await session.send(f"Room '{room_name}' created.")

    elif cmd == "/join":
        if len(parts) < 2:
            await session.send("Usage: /join <room> [password]")
            return
        room_name = parts[1]
        password = parts[2] if len(parts) >= 3 else None
        if room_name not in rooms:
            await session.send(f"Room '{room_name}' does not exist.")
            return
        room_info = rooms[room_name]
        if room_info["password"] and room_info["password"] != password:
            await session.send("Wrong password.")
            return
        # Leave current room
        if session.room in rooms:
            rooms[session.room]["members"].discard(session.username)
        session.room = room_name
        rooms[room_name]["members"].add(session.username)
        logger.info(f"JOIN {session.username} {room_name}")
        await session.send(f"Joined room '{room_name}'.")
        await broadcast_room(room_name, f"*** {session.username} joined {room_name} ***", exclude=session.username)

    else:
        await session.send(f"Unknown command: {cmd}")


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Main coroutine for each connected client."""
    session = ClientSession(reader, writer)
    addr = writer.get_extra_info("peername")

    try:
        # --- Username negotiation ---
        await session.send("Enter your username:")
        for attempt in range(3):
            try:
                username = await asyncio.wait_for(session.readline(), timeout=30)
            except asyncio.TimeoutError:
                await session.send("Timeout. Goodbye.")
                writer.close()
                return

            if not username or len(username) > 32:
                await session.send("Invalid username (1-32 chars). Try again:")
                continue
            if username in clients:
                await session.send(f"Username '{username}' is already taken. Try another:")
                continue
            # Accept
            session.username = username
            break
        else:
            await session.send("Too many failed attempts. Goodbye.")
            writer.close()
            return

        # Register client
        clients[session.username] = session
        session.color_index = hash(session.username) % len(config.COLORS)
        rooms[config.DEFAULT_ROOM]["members"].add(session.username)
        logger.info(f"CONNECT {session.username}")

        # Welcome message — send color_index so client can pick the right color
        await session.send(
            f"Welcome to the chat, {session.username}! "
            f"You are in room '{session.room}'. "
            f"COLOR_INDEX:{session.color_index}"
        )
        await broadcast_room(
            config.DEFAULT_ROOM,
            f"*** {session.username} joined the chat ***",
            exclude=session.username,
        )

        # --- Main message loop ---
        while True:
            try:
                line = await session.readline()
            except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
                break

            if not line:
                continue

            if line.startswith("/"):
                if line.lower() == "/quit":
                    break
                await handle_command(session, line)
            else:
                timestamp = datetime.now().strftime("%H:%M:%S")
                msg = f"[{timestamp}] {session.username} : {line}"
                logger.info(f"MSG {session.username}@{session.room} : {line}")
                await broadcast_room(session.room, msg, exclude=session.username)
                # Echo back to sender
                await session.send(msg)

    except Exception as e:
        logger.error(f"ERROR {e}")
    finally:
        # Cleanup
        username = session.username
        if username:
            clients.pop(username, None)
            if session.room in rooms:
                rooms[session.room]["members"].discard(username)
            logger.info(f"DISCONNECT {username}")
            await broadcast_room(session.room, f"*** {username} left the chat ***")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
async def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else config.DEFAULT_PORT
    host = config.DEFAULT_HOST

    server = await asyncio.start_server(handle_client, host, port)
    addr = server.sockets[0].getsockname()
    print(f"[server] Listening on {addr[0]}:{addr[1]}")
    logger.info(f"SERVER START on {addr[0]}:{addr[1]}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[server] Shutting down.")
