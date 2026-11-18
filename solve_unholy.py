#!/usr/bin/env python3
"""
Exploit for the "Unholy Trinity" CTF challenge.

Usage:
    python solve_unholy.py
    python solve_unholy.py 10.83.2.154 1337

Requires only Python 3 standard library.
Keep your challenge VPN connected while running.
"""

import math
import re
import secrets
import socket
import sys


HOST = "10.83.2.154"
PORT = 1337
E = 17
ROUNDS = 52
SPECIAL = "!@#$%^&*()-+"


class Tube:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError(
                    "Server closed the connection before sending "
                    + repr(marker)
                )
            self.buf += chunk

        end = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def recv_line(self) -> bytes:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Server closed the connection unexpectedly")
            self.buf += chunk

        end = self.buf.index(b"\n") + 1
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def send_line(self, value):
        if isinstance(value, int):
            value = str(value)
        self.sock.sendall(str(value).encode("ascii") + b"\n")


def valid_password_repr(password: bytes) -> bool:
    # This deliberately mirrors the challenge's flawed policy check:
    # it checks str(bytes), not the actual password characters.
    pw = str(password)
    return (
        len(password) > 0
        and any(c.islower() for c in pw)
        and any(c.isupper() for c in pw)
        and any(c.isdigit() for c in pw)
        and any(c in SPECIAL for c in pw)
    )


def make_collision_passwords(N: int, nlen: int):
    """
    Produce distinct fixed-length byte strings P and Q=P+N.
    Then int(P) == int(Q) (mod N), so P^e == Q^e (mod N).
    """
    limit = 1 << (8 * nlen)

    while True:
        # Ensure both P and P+N fit in exactly nlen bytes.
        x = secrets.randbelow(limit - N)
        y = x + N

        p1 = x.to_bytes(nlen, "big")
        p2 = y.to_bytes(nlen, "big")

        if valid_password_repr(p1) and valid_password_repr(p2):
            assert p1 != p2
            assert int.from_bytes(p1, "big") % N == int.from_bytes(p2, "big") % N
            return p1, p2


def integer_nth_root(n: int, k: int) -> int:
    """Return floor(n**(1/k)) using integer arithmetic only."""
    if n < 0 or k <= 0:
        raise ValueError("n must be nonnegative and k positive")
    if n < 2:
        return n

    lo = 0
    hi = 1 << ((n.bit_length() + k - 1) // k)

    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid
    return lo


def extract_flag(text: str):
    found = re.findall(r"PP\{[^}\r\n]*\}", text)
    return found


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    print(f"[+] Connecting to {host}:{port} ...")
    with socket.create_connection((host, port), timeout=15) as sock:
        sock.settimeout(30)
        t = Tube(sock)

        banner = t.recv_until(b"> ").decode("utf-8", errors="replace")
        print(banner, end="")

        match = re.search(r"N=0x([0-9a-fA-F]+),\s*e=0x([0-9a-fA-F]+)", banner)
        if not match:
            raise RuntimeError("Could not parse N and e from the server banner")

        N = int(match.group(1), 16)
        e = int(match.group(2), 16)
        if e != E:
            raise RuntimeError(f"Unexpected exponent: e={e}, expected {E}")

        nlen = (N.bit_length() + 7) // 8
        print(f"[+] Parsed N ({N.bit_length()} bits), e={e}, password length={nlen}")

        # --- Recover FLAG0 through a hash collision during registration ---
        p1, p2 = make_collision_passwords(N, nlen)
        print("[+] Constructed two distinct valid passwords with the same RSA hash")

        def register(username, password):
            t.send_line("1")
            t.recv_until(b"Username: ")
            t.send_line(username)
            t.recv_until(b"Password(hex): ")
            t.send_line(password.hex())
            return t.recv_until(b"> ").decode("utf-8", errors="replace")

        out1 = register("collision_user_a", p1)
        if "Registered" not in out1:
            print(out1)
            raise RuntimeError("First registration did not succeed")

        out2 = register("collision_user_b", p2)
        print(out2, end="")
        flags0 = extract_flag(out2)
        if not flags0:
            raise RuntimeError(
                "The second registration did not reveal a PP{...} flag. "
                "Check that the service is the expected challenge instance."
            )
        print(f"\n[+] FLAG0 = {flags0[0]}")

        # --- Recover the admin secret from the publicly printed commitment ---
        t.send_line("2")
        t.recv_until(b"Username: ")
        t.send_line("admin")
        login_header = t.recv_until(b"Announcement(hex): ").decode(
            "utf-8", errors="replace"
        )

        hmatch = re.search(r"committed pw_hash\s+(\d+)", login_header)
        if not hmatch:
            print(login_header)
            raise RuntimeError("Could not parse admin's committed password hash")

        h = int(hmatch.group(1))
        secret = integer_nth_root(h, e)
        if pow(secret, e) != h:
            raise RuntimeError(
                "The admin hash is not an exact integer 17th power; "
                "the challenge instance may differ from the supplied source."
            )

        print(f"[+] Recovered admin secret ({secret.bit_length()} bits)")
        print(f"[+] Completing {ROUNDS} authentication rounds ...")

        # We have already consumed the first Announcement prompt.
        for rnd in range(ROUNDS):
            if rnd > 0:
                t.recv_until(b"Announcement(hex): ")

            # Prover sends a = r^e, receives challenge c, then sends z = r*s^c.
            while True:
                r = secrets.randbelow(N - 1) + 1
                if math.gcd(r, N) == 1:
                    break

            announcement = pow(r, e, N)
            t.send_line(format(announcement, "x"))

            t.recv_until(b"Challenge: ")
            challenge_line = t.recv_line().strip()
            challenge = int(challenge_line, 10)

            t.recv_until(b"Response(hex): ")
            response = (r * pow(secret, challenge, N)) % N
            t.send_line(format(response, "x"))

        result = t.recv_until(b"> ").decode("utf-8", errors="replace")
        print(result, end="")

        flags1 = extract_flag(result)
        if not flags1:
            raise RuntimeError("Authentication completed, but no PP{...} flag was found")

        print(f"\n[+] FLAG1 = {flags1[0]}")
        print("\n[+] Both flags recovered.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ConnectionError, RuntimeError, ValueError) as exc:
        print(f"\n[-] {exc}", file=sys.stderr)
        sys.exit(1)
