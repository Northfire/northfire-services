# Northfire Services

IRC services (NickServ, ChanServ, MemoServ, OperServ, BotServ, HostServ and the rest) for the [Northfire IRC Network](https://northfire.dev), hardened against password guessing.

Northfire Services is built on [Anope](https://www.anope.org/) 2.1, and stays close to it so upstream releases are easy to merge. Everything Anope does, this does. The changes are listed below, and upstream Anope's own README is in [README.anope.md](README.anope.md).

## What's different from Anope

**Password guessing is limited on every sign-in route** ([nf_authguard](modules/northfire/nf_authguard.cpp))

Stock Anope disconnects someone after a few wrong passwords in one session, but they can reconnect, use SASL, or come from another address and carry on. Northfire Services counts failures across connections, for NickServ IDENTIFY, SASL PLAIN, RECOVER, GROUP, the web panel and the RPC interface:

- **Per address.** 5 failures in 15 minutes locks that address out of signing in for 15 minutes. IPv6 is counted by /64. Each lockout in a row doubles, up to a day.
- **Per account.** 20 failures in an hour, from all addresses together, locks the account for 30 minutes (doubling, up to 6 hours). Addresses the owner has signed in from before are exempt, so guessing can't lock the owner out.
- **Per account and address together.** 5 failures always locks that pair, so being an exempt address doesn't let anyone guess freely (for example, on a shared bouncer).
- A locked-out attempt fails even with the right password, and NickServ says why.
- **Owners are told.** "There were 7 failed sign-in attempts on your account since you last signed in; the last was from 203.0.113.\*…"
- **Staff are told.** Lockouts are logged (category `nf_authguard/alert`) to the log channel and globops. `/msg OperServ AUTHGUARD LIST` and `AUTHGUARD CLEAR <address|account|ALL>` let staff review and lift them.

**Two-step sign-in (optional, per account)** ([nf_twostep](modules/northfire/nf_twostep.cpp))

- `/msg NickServ 2FA ON` gives a key for any authenticator app (Google or Microsoft Authenticator, Aegis, 2FAS, 1Password, Bitwarden...). `2FA CONFIRM <code>` turns it on and shows ten single-use recovery codes.
- After that, the right password isn't enough. NickServ asks for `CODE <code>` from the app, within five minutes and from the same address. A client's SASL sign-in is held the same way, and the client is told to send `CODE` once it has connected.
- Client certificates (`NickServ CERT`, SASL EXTERNAL) still sign in without a code, so bouncers keep working.
- Websites pass the code as a third parameter to `anope.checkCredentials`. Error `-32095` means a code is needed, or the one given was wrong.
- An emailed password reset needs a code too, so an email account alone can't get round it.
- Each code works once. Five wrong codes pause codes for the account for 15 minutes, and the owner is told that someone knows their password.
- Staff can turn it off for someone who lost both their phone and their recovery codes (`2FA RESET <nick>`, privilege `nickserv/twostep/reset`).

**Security notices** ([nf_security](modules/northfire/nf_security.cpp))

- The owner is told when their password, email address or client certificates change, when an emailed reset code is used, and when their password is being guessed from many places.
- Notices go to every connection signed in to the account, as a memo, and by email. After an email change the old address is told too, so a stolen account can't be quietly moved to a new address.
- `/msg NickServ SESSIONS` lists every connection signed in to your account, and the addresses you've signed in from lately.
- `SIGNOUT <nick>` or `SIGNOUT ALL` signs your other connections out. `ALL` also forgets the remembered addresses, so they lose their exemption from the lockouts.

**No weak passwords** ([nf_passpolicy](modules/northfire/nf_passpolicy.cpp))

- `REGISTER`, `SET PASSWORD` and `SASET PASSWORD` refuse a password that's shorter than 8 characters, has the nick in it, or is one of the 100,000 passwords most seen in breaches.
- The list ships with services (`common-passwords.txt`, the NCSC list via SecLists), so nothing is looked up elsewhere.
- Websites can ask the same rules with `northfire.checkPassword`; the forum warns members who sign in with a weak one.

**The forums and IRC** ([nf_forum](modules/northfire/nf_forum.cpp))

- **One-click chat.** For a member it has already signed in, the forum asks for a one-time login code (`northfire.loginToken`). The web chat signs in with it as the password (`nftoken:...`, by SASL or IDENTIFY). A code works once, for one account, for 60 seconds, and counts as the second step, because the forum already asked for the two-step code.
- `northfire.announce` posts a new forum topic in a channel (only the channels in `announce`), `northfire.notify` sends a forum mention to the member (a notice, or a memo when they're away), `northfire.online` lists who's in a public channel, and `northfire.account` gives an account's primary nick and whether it's suspended.
- `/msg NickServ FORUM [nick]` gives the link to a member's forum page.

**Stronger password storage**

- New passwords are hashed with Argon2id. It's set to 19 MiB and 2 passes, sized for a small server, because hashing runs on services' main thread.
- Passwords from older Anope versions (sha256 and the rest) still work, and are re-hashed with Argon2id the next time each person signs in.
- Password hashes and RPC tokens are compared in constant time.
- Random codes (password resets, email confirmations) come from the system's secure random source. Anope used a Mersenne Twister seeded with 32 bits, so anyone who saw a few codes could predict the next ones.

**Passwords only over TLS (optional)** ([nf_tlsonly](modules/northfire/nf_tlsonly.cpp))

When turned on, NickServ refuses IDENTIFY, REGISTER, RECOVER, GROUP and SET PASSWORD from plain-text connections, and tells people how to reconnect with TLS.

**A locked-down RPC interface for websites**

- The JSON-RPC interface listens on 127.0.0.1 only.
- It needs a token, and that token may only call `anope.checkCredentials`, `anope.user` and the `northfire.*` methods above.
- It reads the visitor's address from `X-Forwarded-For`, so a website's sign-in form is limited per visitor rather than as one address.
- A locked-out check returns error `-32096`.

**Smaller changes**

- `/VERSION` and CTCP VERSION say "Northfire Services 1.2 (based on Anope 2.1.27)", and no longer reveal the build flags or which password hash is in use.
- Upgrading from Anope 2.0 works whichever order the database modules are loaded in. `db_json` lets `db_flatfile` import when there's no JSON database yet.
- Core: a sign-in request can be marked as having passed its second step (`SetSecondFactorDone`), and new module events `OnIdentifyGate` (refuse a sign-in attempt), `OnIdentifySecondFactor` (ask for a second step once the password is right) and `OnIdentifyResult` (the outcome), for every route. Refusals carry a reason and a message, and `Mail::SendTo` mails any address.

## Install

On Debian or Ubuntu:

```
sudo apt install build-essential cmake libargon2-dev libssl-dev gettext python3
git clone https://github.com/Northfire/northfire-services.git
cd northfire-services
northfire/install.sh ~/northfire-services
```

Then edit `~/northfire-services/conf/secrets.conf` (the link to your IRC server, and the RPC token) and `local.conf` (your opers), and start it:

```
~/northfire-services/bin/anoperc start
```

The configuration is upstream Anope's, with Northfire's settings applied by [northfire/make-conf.py](northfire/make-conf.py). Northfire's own modules are configured in [northfire.conf](northfire/conf/northfire.conf).

### Upgrading from Anope 2.0

1. Copy your `anope.db` into the new `data/` directory.
2. Add this to `local.conf` for the first start: `module { name = "db_flatfile"; database = "anope.db"; }`
3. Start services. Everything is imported and saved to `anope.json`; remove the `db_flatfile` line afterwards.

Some modules were renamed in Anope 2.1 (for example, `unreal4` is now `unrealircd`, and `m_httpd` is now `httpd`). See [docs/CHANGES.md](docs/CHANGES.md).

## Tests

`tests/docker/run-tests.sh` builds Northfire Services and UnrealIRCd 6 in a Debian 12 container, then runs real IRC clients against them. It covers:

- the lockouts on IDENTIFY, SASL and RPC
- two-step sign-in on IDENTIFY, SASL and RPC: recovery codes, replayed codes, wrong-code pauses, staff reset, and surviving a restart
- security notices (as notices, memos and email, including to the old address), SESSIONS and SIGNOUT
- the staff commands, owner notices and log alerts
- TLS-only mode
- the version replies
- a full upgrade from a 2.0 database, including re-hashing an old password

## Credits and licence

Northfire Services is free software under the GNU General Public License, version 2 ([docs/LICENSE.txt](docs/LICENSE.txt)), as Anope is.

Anope is by the Anope Team and its contributors ([docs/AUTHORS.txt](docs/AUTHORS.txt)). Anope is based on Epona by Lara, which in turn came from IRC Services by Andy Church. Their copyright notices are kept in the source files.

Northfire's changes are by Kyle Bargman for the Northfire IRC Network.
