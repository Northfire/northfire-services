#!/usr/bin/env python3
"""Northfire Services integration tests: real IRC clients against UnrealIRCd + services.

Built by Kyle Bargman, 2026-11-22. Runs inside the test container (see run-tests.sh).
Usage: irc_test.py authguard | branding | tlsonly | upgrade | upgrade-again | rpc
"""

import base64
import json
import re
import socket
import ssl
import sys
import time
import urllib.request

HOST = "127.0.0.1"
PASSED = []


class Client:
    def __init__(self, nick, tls=True, sasl=None):
        raw = socket.create_connection((HOST, 6697 if tls else 6667), timeout=10)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw)
        self.s = raw
        self.buf = b""
        self.nick = nick
        self.sasl_result = None
        if sasl:
            self.send("CAP REQ :sasl")
        self.send(f"NICK {nick}")
        self.send(f"USER {nick.lower()} 0 * :test")
        if sasl:
            self.wait(r" CAP .* ACK ")
            self.send("AUTHENTICATE PLAIN")
            self.wait(r"^AUTHENTICATE \+")
            blob = base64.b64encode(f"{sasl[0]}\0{sasl[0]}\0{sasl[1]}".encode()).decode()
            self.send(f"AUTHENTICATE {blob}")
            line = self.wait(r" (903|904|905|906) ")
            self.sasl_result = line.split()[1]
            self.send("CAP END")
        self.wait(r" 001 ")

    def send(self, line):
        self.s.sendall((line + "\r\n").encode())

    def lines(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                line = line.decode("utf-8", "replace").rstrip("\r")
                if line.startswith("PING"):
                    self.send("PONG" + line[4:])
                    continue
                yield line
            self.s.settimeout(max(0.05, end - time.time()))
            try:
                data = self.s.recv(4096)
            except (socket.timeout, TimeoutError):
                return
            if not data:
                return
            self.buf += data

    def wait(self, pattern, timeout=8):
        for line in self.lines(timeout):
            if re.search(pattern, line):
                return line
        raise AssertionError(f"{self.nick}: timed out waiting for {pattern!r}")

    def ns(self, text, expect, timeout=8):
        """Message NickServ and return its first notice matching expect."""
        self.send(f"PRIVMSG NickServ :{text}")
        for line in self.lines(timeout):
            if line.startswith(":NickServ!") and re.search(expect, line):
                return line
        raise AssertionError(f"{self.nick}: NickServ didn't say {expect!r} to {text!r}")

    def os(self, text, expect, timeout=8):
        self.send(f"PRIVMSG OperServ :{text}")
        got = []
        matched = False
        for line in self.lines(timeout):
            if line.startswith(":OperServ!"):
                got.append(line)
                matched = matched or bool(re.search(expect, line))
            if matched:
                got += [l for l in self.lines(0.7) if l.startswith(":OperServ!")]
                return got
        raise AssertionError(f"{self.nick}: OperServ didn't say {expect!r}; got {got}")

    def notices_from(self, who, timeout=2):
        return [l for l in self.lines(timeout) if l.startswith(f":{who}!")]

    def quit(self):
        try:
            self.send("QUIT :bye")
            self.s.close()
        except OSError:
            pass


def ok(name):
    PASSED.append(name)
    print("  ok -", name, flush=True)


def register(nick, password):
    c = Client(nick)
    c.ns(f"REGISTER {password} {nick.lower()}@test.local", r"\bregistered\b")
    c.quit()


def oper():
    c = Client("testoper")
    c.ns("REGISTER operpass1234 oper@test.local", r"registered|already")
    c.ns("IDENTIFY operpass1234", r"Password accepted|already identified")
    c.send("OPER testoper testoperpass")
    c.wait(r" 381 ")
    return c


def test_authguard():
    print("authguard:")
    op = oper()
    register("Bob", "rightpass1234")

    # 1. Five wrong passwords from one address lock the address (and the account from it)
    c = Client("Guest1")
    for i in range(4):
        c.ns("IDENTIFY Bob wrongpass", r"Password incorrect|incorrect")
    c.ns("IDENTIFY Bob wrongpass", r"incorrect")  # 5th: counted, now locked
    ok("four wrong passwords are just 'incorrect'")
    c.wait(r"KILL|ERROR|Closing Link")  # Anope's own badpasslimit still disconnects
    ok("five bad passwords in one session still disconnect (badpasslimit)")
    c = Client("Guest1b")
    c.ns("IDENTIFY Bob rightpass1234", r"Too many failed sign-in attempts")
    ok("after five, even the right password is refused")
    c.quit()

    # 2. Staff can see and clear it
    got = op.os("AUTHGUARD LIST", r"End of|account|address")
    text = " ".join(got)
    assert "127.0.0.1" in text and "Bob" in text, text
    ok("OperServ AUTHGUARD LIST shows the address and the account")
    op.os("AUTHGUARD CLEAR ALL", r"Cleared")
    ok("OperServ AUTHGUARD CLEAR ALL")

    # 3. The owner is told about the failures when they sign in
    c = Client("Guest2")
    c.ns("IDENTIFY Bob rightpass1234", r"Password accepted")
    warn = " ".join(c.notices_from("NickServ"))
    assert re.search(r"\x02?5\x02? failed sign-in attempts", warn), warn
    assert "127.0.0.*" in warn, warn
    ok("owner is told: 5 failed attempts, address shown as 127.0.0.*")
    c.quit()

    # 4. Now 127.0.0.1 is trusted for Bob: the address lock doesn't apply to Bob,
    #    but the account+address limit still does.
    c = Client("Guest3")
    for i in range(5):
        c.ns("IDENTIFY Bob wrongpass", r"incorrect")
    c = Client("Guest3b")
    c.ns("IDENTIFY Bob rightpass1234", r"Too many failed sign-in attempts")
    ok("a trusted address still hits the account+address limit")
    c.quit()
    op.os("AUTHGUARD CLEAR Bob", r"Cleared")

    # 5. SASL failures count too, and a locked SASL attempt fails
    register("Carol", "carolpass1234")
    for i in range(5):
        c = Client(f"Sasl{i}", sasl=("Carol", "nope"))
        assert c.sasl_result == "904", c.sasl_result
        c.quit()
    ok("SASL PLAIN with a wrong password fails (904)")
    c = Client("Sasl9", sasl=("Carol", "carolpass1234"))
    assert c.sasl_result == "904", c.sasl_result
    c.quit()
    ok("after five SASL failures, SASL with the right password is refused")
    c = Client("Guest4")
    c.ns("IDENTIFY Carol carolpass1234", r"Too many failed")
    ok("...and so is IDENTIFY from the same address")
    c.quit()
    op.os("AUTHGUARD CLEAR 127.0.0.1", r"Cleared")
    c = Client("Sasl10", sasl=("Carol", "carolpass1234"))
    assert c.sasl_result == "903", c.sasl_result
    ok("after CLEAR (by address), SASL works (903)")
    c.quit()

    # 6. Guessing at accounts that don't exist still counts against the address
    #    (checked with Gina, who has never signed in from here)
    register("Gina", "ginapass1234")
    c = Client("Guest5")
    for i in range(5):
        c.ns(f"IDENTIFY Nobody{i} whatever", r"isn't registered|not registered")
    c = Client("Guest5b")
    c.ns("IDENTIFY Gina ginapass1234", r"Too many failed")
    ok("guessing at unregistered nicks locks the address too")
    c.ns("IDENTIFY Carol carolpass1234", r"Password accepted")
    ok("...but not for accounts that have signed in from it before")
    c.quit()
    op.os("AUTHGUARD CLEAR ALL", r"Cleared|No lockout")

    # 7. Alerts go to the log channel (#services)
    op.send("JOIN #services")
    op.wait(r" 366 ")
    c = Client("Guest6")
    for i in range(5):
        c.ns("IDENTIFY Bob wrongpass", r"incorrect|Too many")
    alerts = [l for l in op.lines(3) if "#services" in l and "NF_AUTHGUARD" in l.upper()]
    assert any("locked" in l for l in alerts), alerts
    ok("a lockout is announced in #services")
    c.quit()
    op.os("AUTHGUARD CLEAR ALL", r"Cleared|No lockout")
    op.quit()


def test_branding():
    print("branding:")
    c = Client("Curious")
    c.send("VERSION services.northfire.net")
    line = c.wait(r" 351 ")
    assert "Northfire Services" in line and "enc_" not in line, line
    c.send("PRIVMSG NickServ :\x01VERSION\x01")
    line = c.wait(r"NOTICE Curious :\x01VERSION")
    assert "Northfire Services" in line and "enc_" not in line, line
    ok("/VERSION and CTCP VERSION say Northfire Services, and nothing about password hashing")
    c.quit()


def test_tlsonly():
    print("tlsonly:")
    register("Dave", "davepass1234")
    c = Client("Plain1", tls=False)
    c.ns("IDENTIFY Dave davepass1234", r"secure connection|TLS")
    ok("IDENTIFY over plain text is refused, with how to fix it")
    c.ns("REGISTER somepass1234 x@test.local", r"secure connection|TLS")
    ok("REGISTER over plain text is refused")
    c.quit()
    c = Client("Secure1")
    c.ns("IDENTIFY Dave davepass1234", r"Password accepted")
    ok("IDENTIFY over TLS works")
    c.quit()


def saved_pass(account):
    """Erin's stored password hash, after asking services to save the database."""
    op = oper()
    op.os("UPDATE", r"Updating|update")
    op.quit()
    time.sleep(1)
    with open("/work/test/data/anope.json") as f:
        db = json.load(f)
    for obj in db.get("data", {}).get("NickCore", []):
        if obj.get("display") == account:
            return obj.get("pass", "")
    raise AssertionError(f"{account} not in anope.json")


def test_upgrade():
    print("upgrade from a 2.0 database:")
    c = Client("Erin")
    c.ns("IDENTIFY erinpass1234", r"Password accepted")
    ok("a 2.0 account (sha256 password) signs in after the import")
    c.send("PRIVMSG ChanServ :INFO #erin")
    line = c.wait(r"Founder: .*Erin")
    ok("its 2.0 channel came across with its founder")
    c.quit()
    h = saved_pass("Erin")
    assert h.startswith("argon2") or h.startswith("$argon2"), h[:20]
    ok("the password was re-hashed with Argon2 on sign-in (" + h.split("$")[0][:12] + "...)")


def test_upgrade_again():
    print("after the import (db_json only):")
    c = Client("Erin")
    c.ns("IDENTIFY erinpass1234", r"Password accepted")
    ok("the same password works with the Argon2 hash, after a restart without db_flatfile")
    c.quit()
    c = Client("NotErin")
    c.ns("IDENTIFY Erin wrongpass", r"incorrect")
    ok("a wrong password is still refused")
    c.quit()


def rpc(method, params, token="testrpctoken", xff=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request("http://127.0.0.1:8091/jsonrpc", data=body,
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + base64.b64encode(token.encode()).decode()})
    if xff:
        req.add_header("X-Forwarded-For", xff)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def test_rpc():
    print("rpc:")
    register("Fay", "faypass12345")
    st, r = rpc("anope.checkCredentials", ["Fay", "faypass12345"])
    assert r.get("result", {}).get("account") == "Fay", r
    ok("checkCredentials with the right password")
    st, r = rpc("anope.checkCredentials", ["Fay", "faypass12345"], token="wrong")
    assert st in (401, 403) or "error" in r, (st, r)
    ok("a wrong token is refused")
    st, r = rpc("anope.listAccounts", [])
    assert "error" in r or st in (401, 403), (st, r)
    ok("the token can't call methods outside its list (anope.listAccounts)")
    for i in range(5):
        st, r = rpc("anope.checkCredentials", ["Fay", "bad"], xff="203.0.113.7")
    st, r = rpc("anope.checkCredentials", ["Fay", "faypass12345"], xff="203.0.113.7")
    assert r.get("error", {}).get("code") == -32096, r
    ok("five failures from one forum visitor lock that visitor (-32096)")
    st, r = rpc("anope.checkCredentials", ["Fay", "faypass12345"], xff="198.51.100.9")
    assert r.get("result", {}).get("account") == "Fay", r
    ok("...but not other forum visitors (counted by X-Forwarded-For)")


if __name__ == "__main__":
    for name in sys.argv[1:]:
        globals()["test_" + name.replace("-", "_")]()
    print(f"{len(PASSED)} checks passed")
