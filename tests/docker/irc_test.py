#!/usr/bin/env python3
"""Northfire Services integration tests: real IRC clients against UnrealIRCd + services.

Built by Kyle Bargman, 2026-11-22. Runs inside the test container (see run-tests.sh).
Usage: irc_test.py authguard | branding | tlsonly | upgrade | upgrade-again | rpc | security | twostep | twostep-again
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
    def __init__(self, nick, tls=True, sasl=None, cert=None, external=False):
        raw = socket.create_connection((HOST, 6697 if tls else 6667), timeout=10)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if cert:  # Built by Kyle Bargman: a client certificate (CertFP)
                ctx.load_cert_chain(cert)
            raw = ctx.wrap_socket(raw)
        self.s = raw
        self.buf = b""
        self.nick = nick
        self.sasl_result = None
        if sasl or external:
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
        if external:  # Built by Kyle Bargman: SASL EXTERNAL (the certificate is the login)
            self.wait(r" CAP .* ACK ")
            self.send("AUTHENTICATE EXTERNAL")
            self.wait(r"^AUTHENTICATE \+")
            self.send("AUTHENTICATE +")
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
    register("Carol", "amber-lake-41")
    for i in range(5):
        c = Client(f"Sasl{i}", sasl=("Carol", "nope"))
        assert c.sasl_result == "904", c.sasl_result
        c.quit()
    ok("SASL PLAIN with a wrong password fails (904)")
    c = Client("Sasl9", sasl=("Carol", "amber-lake-41"))
    assert c.sasl_result == "904", c.sasl_result
    c.quit()
    ok("after five SASL failures, SASL with the right password is refused")
    c = Client("Guest4")
    c.ns("IDENTIFY Carol amber-lake-41", r"Too many failed")
    ok("...and so is IDENTIFY from the same address")
    c.quit()
    op.os("AUTHGUARD CLEAR 127.0.0.1", r"Cleared")
    c = Client("Sasl10", sasl=("Carol", "amber-lake-41"))
    assert c.sasl_result == "903", c.sasl_result
    ok("after CLEAR (by address), SASL works (903)")
    c.quit()

    # 6. Guessing at accounts that don't exist still counts against the address
    #    (checked with Gina, who has never signed in from here)
    register("Gina", "quiet-fern-72")
    c = Client("Guest5")
    for i in range(5):
        c.ns(f"IDENTIFY Nobody{i} whatever", r"isn't registered|not registered")
    c = Client("Guest5b")
    c.ns("IDENTIFY Gina quiet-fern-72", r"Too many failed")
    ok("guessing at unregistered nicks locks the address too")
    c.ns("IDENTIFY Carol amber-lake-41", r"Password accepted")
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
    register("Dave", "stone-bridge-63")
    c = Client("Plain1", tls=False)
    c.ns("IDENTIFY Dave stone-bridge-63", r"secure connection|TLS")
    ok("IDENTIFY over plain text is refused, with how to fix it")
    c.ns("REGISTER somepass1234 x@test.local", r"secure connection|TLS")
    ok("REGISTER over plain text is refused")
    c.quit()
    c = Client("Secure1")
    c.ns("IDENTIFY Dave stone-bridge-63", r"Password accepted")
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


def mail_log():
    """Everything services has emailed so far (tests/docker/fake-sendmail.sh). Built by Kyle Bargman"""
    time.sleep(1)  # mail is sent from a thread
    try:
        with open("/work/test/mail.log") as f:
            return f.read()
    except OSError:
        return ""


def test_security():
    """nf_security: notices for account changes, SESSIONS and SIGNOUT. Built by Kyle Bargman"""
    print("security notices and sessions:")
    register("Hank", "copper-owl-58")
    a = Client("Hank")
    a.ns("IDENTIFY copper-owl-58", r"Password accepted")
    b = Client("HankPhone")
    b.ns("IDENTIFY Hank copper-owl-58", r"Password accepted")

    a.ns("SET PASSWORD harbor-light-77", r"changed|set to")
    note = " ".join(b.notices_from("NickServ", 3))
    assert "Security notice" in note and "password" in note and "Hank" in note, note
    ok("a password change is announced to the account's other connections")
    mails = mail_log()
    assert 'To: "Hank" <hank@test.local>' in mails and "your password was changed" in mails, mails[-600:]
    ok("...and emailed to the account's address")

    a.ns("SET EMAIL hank2@test.local", r"changed|set to|confirm")
    note = " ".join(b.notices_from("NickServ", 3))
    assert "email address" in note and "hank@test.local" in note and "hank2@test.local" in note, note
    mails = mail_log()
    tos = set()
    for block in re.split(r"(?=From: )", mails):
        if "your email address was changed" in block:
            tos.update(re.findall(r"^To: .*<(.*)>", block, re.M))
    assert tos == {"hank@test.local", "hank2@test.local"}, tos
    ok("an email change is announced, and the OLD address is emailed too")

    b.send("PRIVMSG MemoServ :READ LAST")
    memo = " ".join(l for l in b.lines(3) if l.startswith(":MemoServ!"))
    assert "Security notice" in memo, memo
    ok("the notices are also kept as memos")

    a.send("PRIVMSG NickServ :SESSIONS")
    lines = " ".join(a.notices_from("NickServ", 3))
    assert "HankPhone" in lines and "(this connection)" in lines and "TLS" in lines, lines
    ok("SESSIONS lists both connections")

    a.ns("SIGNOUT ALL", r"Signed out")
    b.wait(r"signed out of your account")
    ok("SIGNOUT ALL signs out the other connection")
    b.ns("SESSIONS", r"must be logged into an account")
    ok("...which is no longer signed in")
    a.quit()
    b.quit()


def totp(key32, step):
    """RFC 6238 code for one 30-second step, as an authenticator app would show it."""
    import hashlib
    import hmac
    import struct
    key = base64.b32decode(key32 + "=" * (-len(key32) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[19] & 15
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


def test_twostep():
    """nf_twostep: authenticator-app codes. Built by Kyle Bargman"""
    print("two-step sign-in:")
    op = oper()
    register("Ivy", "ivypass12345")
    a = Client("Ivy")
    a.ns("IDENTIFY ivypass12345", r"Password accepted")
    a.ns("2FA", r"is \x02?off")
    a.send("PRIVMSG NickServ :2FA ON")
    got = " ".join(a.notices_from("NickServ", 3))
    key = re.search(r"secret=([A-Z2-7]+)", got).group(1)
    assert len(key) == 32, key
    ok("2FA ON gives a 160-bit key and an otpauth link")
    a.ns("2FA CONFIRM 000000" if totp(key, int(time.time()) // 30) != "000000" else "2FA CONFIRM 111111", r"isn't right")
    step = int(time.time()) // 30
    a.send(f"PRIVMSG NickServ :2FA CONFIRM {totp(key, step)}")
    got = " ".join(a.notices_from("NickServ", 3))
    assert "now \x02on" in got, got
    codes = re.findall(r"\b[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}\b", got)
    assert len(codes) == 10, codes
    ok("2FA CONFIRM with the app's code turns it on and shows 10 recovery codes")
    last = step

    c = Client("IvyLaptop")
    c.ns("IDENTIFY Ivy ivypass12345", r"two-step sign-in.*CODE")
    ok("IDENTIFY with the right password asks for the code")
    c.ns("SESSIONS", r"must be logged into an account")
    ok("...and doesn't sign in yet")
    last += 1
    c.ns(f"CODE {totp(key, last)}", r"Code accepted")
    ok("CODE with the app's next code signs in")
    c.quit()  # the test network allows 3 connections per address, as omen does

    d = Client("IvyTablet")
    d.ns("IDENTIFY Ivy ivypass12345", r"two-step")
    d.ns(f"CODE {totp(key, last)}", r"isn't right")
    ok("a code can't be used twice")
    d.ns(f"CODE {codes[0]}", r"Code accepted")
    ok("a recovery code works instead")
    note = " ".join(a.notices_from("NickServ", 2))
    assert "recovery code was used" in note and "9" in note, note
    ok("...and the owner is told (9 left)")
    d.quit()

    st, r = rpc("anope.checkCredentials", ["Ivy", "ivypass12345"], xff="198.51.100.20")
    assert r.get("error", {}).get("code") == -32095, r
    ok("the website gets -32095 without a code")
    st, r = rpc("anope.checkCredentials", ["Ivy", "ivypass12345", "123456"], xff="198.51.100.20")
    assert r.get("error", {}).get("code") == -32095, r
    st, r = rpc("anope.checkCredentials", ["Ivy", "ivypass12345", codes[1]], xff="198.51.100.20")
    assert r.get("result", {}).get("account") == "Ivy", r
    ok("...and signs in with the code as a third parameter")
    st, r = rpc("anope.checkCredentials", ["Ivy", "wrongpass", codes[2]], xff="198.51.100.21")
    assert r.get("error", {}).get("code") == -32098, r
    ok("a code doesn't help a wrong password")

    s = Client("IvySasl", sasl=("Ivy", "ivypass12345"))
    assert s.sasl_result == "904", s.sasl_result
    s.wait(r"NickServ.*two-step sign-in.*CODE")
    ok("SASL PLAIN is held, and the client is told to send CODE")
    s.ns(f"CODE {codes[2]}", r"Code accepted")
    ok("...and CODE finishes it")
    s.quit()

    e = Client("IvyThief")
    e.ns("IDENTIFY Ivy ivypass12345", r"two-step")
    for guess in ("111111", "222222", "333333", "444444"):
        e.ns(f"CODE {guess}", r"isn't right")
    e.ns("CODE 555555", r"isn't right")
    note = " ".join(a.notices_from("NickServ", 2))
    assert "they know your password" in note, note
    ok("five wrong codes tell the owner their password is known")
    e.ns("IDENTIFY Ivy ivypass12345", r"Too many wrong")
    ok("...and codes are paused for the account")
    e.quit()

    op.ns("2FA RESET Ivy", r"now off")
    note = " ".join(a.notices_from("NickServ", 2))
    assert "turned off" in note and "staff" in note, note
    ok("staff 2FA RESET turns it off, and the owner is told")
    f = Client("IvyAgain")
    f.ns("IDENTIFY Ivy ivypass12345", r"Password accepted")
    ok("after RESET the password alone works again")
    f.quit()
    a.quit()
    op.quit()

    # Left on for twostep-again (after a restart)
    register("Jo", "jopass123456")
    j = Client("Jo")
    j.ns("IDENTIFY jopass123456", r"Password accepted")
    j.send("PRIVMSG NickServ :2FA ON")
    key = re.search(r"secret=([A-Z2-7]+)", " ".join(j.notices_from("NickServ", 3))).group(1)
    j.ns(f"2FA CONFIRM {totp(key, int(time.time()) // 30)}", r"now \x02on")
    j.quit()
    with open("/work/jo.key", "w") as f:
        f.write(key)
    saved_pass("Jo")  # OperServ UPDATE saves the database


def test_twostep_again():
    """After a restart, two-step sign-in is still on. Built by Kyle Bargman"""
    print("two-step sign-in after a restart:")
    with open("/work/jo.key") as f:
        key = f.read().strip()
    c = Client("JoAgain")
    c.ns("IDENTIFY Jo jopass123456", r"two-step")
    ok("two-step sign-in is still on after a restart")
    c.ns(f"CODE {totp(key, int(time.time()) // 30 + 1)}", r"Code accepted")
    ok("...with the same key")
    c.quit()


def test_passpolicy():
    """nf_passpolicy: no weak passwords. Built by Kyle Bargman"""
    print("password rules:")
    c = Client("Kira")
    c.ns("REGISTER password1 kira@test.local", r"most common")
    ok("REGISTER refuses one of the most common passwords")
    c.ns("REGISTER kira-2024-xyz kira@test.local", r"nick in it")
    ok("...and one with the nick in it")
    c.ns("REGISTER s1x7q kira@test.local", r"too short")
    ok("...and one that's too short")
    c.ns("REGISTER violet-river-29 kira@test.local", r"\bregistered\b")
    ok("a good password registers")
    c.ns("SET PASSWORD qwertyuiop", r"most common")
    ok("SET PASSWORD refuses a common one too")
    c.ns("SET PASSWORD orchid-tower-35", r"changed to|password .*changed|Password for")
    ok("...and takes a good one")
    c.quit()
    st, r = rpc("northfire.checkPassword", ["letmein123"])
    assert r.get("result", {}).get("ok") is False, r
    st, r = rpc("northfire.checkPassword", ["violet-river-29", "Kira"])
    assert r.get("result", {}).get("ok") is True, r
    ok("the forum can ask the same rules (northfire.checkPassword)")


def test_forum():
    """nf_forum: one-click chat codes and the forum's calls. Built by Kyle Bargman"""
    print("forum and IRC:")
    register("Lena", "maple-cloud-84")
    st, r = rpc("northfire.loginToken", ["lena"])
    tok = r.get("result", {}).get("token", "")
    assert tok.startswith("nftoken:") and r["result"].get("account") == "Lena", r
    ok("the forum gets a one-time login code, with the primary nick")
    a = Client("Lena", sasl=("Lena", tok))
    assert a.sasl_result == "903", a.sasl_result
    ok("SASL with the code signs in")
    b = Client("LenaTwo")
    b.ns(f"IDENTIFY Lena {tok}", r"incorrect")
    ok("a code works only once")
    st, r = rpc("northfire.loginToken", ["Lena"])
    b.ns("IDENTIFY Lena " + r["result"]["token"], r"Password accepted")
    ok("IDENTIFY with a fresh code works too")
    b.quit()
    st, r = rpc("northfire.loginToken", ["Jo"])  # Jo has two-step sign-in on (twostep test)
    j = Client("JoForum", sasl=("Jo", r["result"]["token"]))
    assert j.sasl_result == "903", j.sasl_result
    ok("a code counts as the second step (the forum asked for the two-step code)")
    j.quit()
    st, r = rpc("northfire.loginToken", ["nobody-here"])
    assert "error" in r, r
    ok("no code for an account that doesn't exist")

    st, r = rpc("northfire.account", ["lena"])
    assert r.get("result", {}).get("account") == "Lena" and r["result"].get("suspended") is False and r["result"].get("online") is True, r
    ok("northfire.account: primary nick, not suspended, online")
    st, r = rpc("northfire.notify", ["Lena", "Kira mentioned you in Hello world"])
    line = a.wait(r"NickServ!.*\[Forums\] Kira mentioned you")
    ok("northfire.notify reaches the account on IRC")
    a.send("JOIN #Northfire")
    a.wait(r" 366 ")
    st, r = rpc("northfire.online", ["#Northfire"])
    assert "Lena" in r.get("result", {}).get("nicks", []), r
    ok("northfire.online lists who's in a public channel")
    a.send("JOIN #hidden")
    a.wait(r" 366 .*#hidden")
    a.send("MODE #hidden +s")
    time.sleep(1)
    st, r = rpc("northfire.online", ["#hidden"])
    assert "error" in r, r
    ok("...but not a secret one")
    st, r = rpc("northfire.announce", ["#Northfire", "New topic: Hello world https://northfire.dev/forums/t/1"])
    a.wait(r"ChanServ!.* PRIVMSG #Northfire :New topic: Hello world")
    ok("northfire.announce posts in an allowed channel")
    st, r = rpc("northfire.announce", ["#hidden", "spam"])
    assert "error" in r, r
    ok("...and nowhere else")
    a.ns("FORUM Lena", r"https://northfire.dev/forums/u/Lena")
    ok("NickServ FORUM gives the member's page")
    a.quit()


def test_devicecert():
    """The Northfire app's "Remember this computer": CERT ADD <fingerprint>, then SASL EXTERNAL. Built by Kyle Bargman"""
    print("remember this computer:")
    import hashlib, subprocess
    pem = "/work/device.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30",
                    "-subj", "/CN=Mia laptop", "-keyout", pem, "-out", pem + ".crt"], check=True, capture_output=True)
    with open(pem, "a") as f:
        f.write(open(pem + ".crt").read())
    der = ssl.PEM_cert_to_DER_cert(open(pem + ".crt").read())
    fp = hashlib.sha256(der).hexdigest()
    register("Mia", "silver-moon-26")
    a = Client("Mia", cert=pem)  # the app's next connection uses the new certificate
    a.ns("IDENTIFY silver-moon-26", r"Password accepted")
    a.ns("CERT ADD", r"added to")
    ok("signed in on a connection with the new certificate, CERT ADD adds it")
    b = Client("MiaPhone", cert=pem, external=True)
    assert b.sasl_result == "903", b.sasl_result
    ok("the next connection signs in with SASL EXTERNAL, no password")
    note = " ".join(a.notices_from("NickServ", 2))
    assert "certificate" in note and "added" in note, note
    ok("...and the owner was told a certificate was added")
    b.quit()
    a.quit()


if __name__ == "__main__":
    for name in sys.argv[1:]:
        globals()["test_" + name.replace("-", "_")]()
    print(f"{len(PASSED)} checks passed")
