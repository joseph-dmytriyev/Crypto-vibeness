"""
Integration tests for Dev 1 — server.py + client.py
Run: python test_dev1.py
"""
import subprocess
import socket
import time
import os
import glob
import sys

PASS = []
FAIL = []


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


# Start server
srv = subprocess.Popen(
    [sys.executable, "server.py"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
time.sleep(1.0)

try:
    # Test 1: server accepts connection
    s1 = socket.socket()
    s1.settimeout(3)
    s1.connect(("localhost", 9000))
    # read "Enter your username:" prompt
    buf = b""
    while b"\n" not in buf:
        buf += s1.recv(1024)
    s1.send(b"alice\n")
    time.sleep(0.5)
    resp1 = s1.recv(2048).decode(errors="ignore")
    check("server accepts connection", len(resp1) > 0, resp1[:80])

    # Test 2: duplicate username refused
    s2 = socket.socket()
    s2.settimeout(3)
    s2.connect(("localhost", 9000))
    buf2 = b""
    while b"\n" not in buf2:
        buf2 += s2.recv(1024)
    s2.send(b"alice\n")
    time.sleep(0.5)
    resp2 = s2.recv(2048).decode(errors="ignore")
    check(
        "duplicate username refused",
        "taken" in resp2.lower() or "already" in resp2.lower() or "exist" in resp2.lower(),
        resp2[:80],
    )
    s2.close()

    # Test 3: second unique user connects
    s3 = socket.socket()
    s3.settimeout(3)
    s3.connect(("localhost", 9000))
    buf3 = b""
    while b"\n" not in buf3:
        buf3 += s3.recv(1024)
    s3.send(b"bob\n")
    time.sleep(0.5)
    resp3 = s3.recv(2048).decode(errors="ignore")
    check("second user connects", len(resp3) > 0, resp3[:80])

    # Test 4: message broadcast in same room
    s1.send(b"hello from alice\n")
    time.sleep(0.5)
    msg = s3.recv(2048).decode(errors="ignore")
    check(
        "message broadcast in room",
        "alice" in msg.lower() or "hello" in msg.lower(),
        msg[:80],
    )

    # Test 5: list command works
    s1.send(b"/list\n")
    time.sleep(0.5)
    rooms = s1.recv(2048).decode(errors="ignore")
    check("/list returns rooms", "general" in rooms.lower(), rooms[:80])

    # Test 6: create room
    s1.send(b"/create testroom\n")
    time.sleep(0.3)
    s1.send(b"/list\n")
    time.sleep(0.5)
    rooms2 = s1.recv(4096).decode(errors="ignore")
    check("/create adds room", "testroom" in rooms2.lower(), rooms2[:80])

    # Test 7: join room — messages isolated per room
    s1.send(b"/join testroom\n")
    time.sleep(0.3)
    s1.send(b"msg in testroom\n")
    time.sleep(0.5)
    s3.settimeout(0.8)
    try:
        leak = s3.recv(2048).decode(errors="ignore")
        check(
            "messages isolated per room",
            "msg in testroom" not in leak,
            "message leaked: " + leak[:80],
        )
    except Exception:
        check("messages isolated per room", True)

    # Test 8: log file exists and has content
    logs = glob.glob("logs/log_*.txt")
    check("log file created", len(logs) > 0)
    if logs:
        content = open(logs[-1]).read()
        check("log file has events", len(content) > 10, content[:120])

    s1.close()
    s3.close()

finally:
    srv.terminate()
    time.sleep(0.3)

print(f"\n{'='*40}")
print(f"  {len(PASS)} passed  |  {len(FAIL)} failed")
if FAIL:
    print(f"  Failed: {', '.join(FAIL)}")
    sys.exit(1)
else:
    print("  All tests passed — ready to merge")
