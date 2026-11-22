#!/usr/bin/env python3
"""Write a small Anope 2.0 (db_flatfile) database for the upgrade test.

Built by Kyle Bargman, 2026-11-22. Erin's password is hashed the way Anope 2.0's
enc_sha256 did it (SHA-256 with a random initial state, stored as
sha256:<hash hex>:<iv hex>), so the test proves 2.1 still accepts old passwords
and re-hashes them with Argon2.
Usage: make_old_db.py <out file>
"""

import os
import struct
import sys
import time

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def sha256_with_iv(data, h):
    """Plain SHA-256, but starting from the state h (8 words) instead of the standard one."""
    rotr = lambda x, n: ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    msg = data + b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack(">Q", len(data) * 8)
    h = list(h)
    for off in range(0, len(msg), 64):
        w = list(struct.unpack(">16I", msg[off:off + 64]))
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) & 0xFFFFFFFF
            t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFF
            a, b, c, d, e, f, g, hh = (t1 + t2) & 0xFFFFFFFF, a, b, c, (d + t1) & 0xFFFFFFFF, e, f, g
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return struct.pack(">8I", *h)


def anope20_sha256(password):
    iv = struct.unpack(">8I", os.urandom(32))
    digest = sha256_with_iv(password.encode(), iv)
    return f"sha256:{digest.hex()}:{struct.pack('>8I', *iv).hex()}"


def main():
    # The custom-IV SHA-256 must equal hashlib's with the standard IV
    import hashlib
    std = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    assert sha256_with_iv(b"abc" * 30, std) == hashlib.sha256(b"abc" * 30).digest()

    now = int(time.time())
    objects = [
        ("NickCore", 1, [("display", "Erin"), ("uniqueid", "1001"), ("pass", anope20_sha256("erinpass1234")),
                         ("email", "erin@test.local"), ("language", ""), ("access", ""), ("memomax", "20"),
                         ("MEMO_SIGNON", "1"), ("MEMO_RECEIVE", "1"), ("cert", ""), ("HIDE_EMAIL", "1"),
                         ("NS_PRIVATE", "1"), ("AUTOOP", "1"), ("NS_SECURE", "1")]),
        ("NickAlias", 2, [("nick", "Erin"), ("last_quit", "bye"), ("last_realname", "Erin"),
                          ("last_usermask", "erin@test.local"), ("last_realhost", "erin@127.0.0.1"),
                          ("time_registered", str(now - 86400 * 400)), ("last_seen", str(now - 3600)), ("nc", "Erin")]),
        ("ChannelInfo", 3, [("name", "#erin"), ("founder", "Erin"), ("description", "Erin's channel"),
                            ("time_registered", str(now - 86400 * 300)), ("last_used", str(now - 3600)),
                            ("last_topic", "Welcome to #erin"), ("last_topic_setter", "Erin"),
                            ("last_topic_time", str(now - 7200)), ("bantype", "2"), ("levels", ""), ("bi", ""),
                            ("banexpire", "0"), ("memomax", "0"), ("PEACE", "1"), ("SECUREFOUNDER", "1"),
                            ("KEEPTOPIC", "1")]),
    ]
    out = []
    for kind, oid, fields in objects:
        out.append(f"OBJECT {kind}\nID {oid}\n" + "".join(f"DATA {k} {v}\n" for k, v in fields) + "END\n")
    with open(sys.argv[1], "w") as f:
        f.write("".join(out))
    print("wrote", sys.argv[1])


if __name__ == "__main__":
    main()
