/*
 * Northfire Services: nf_twostep - two-step sign-in with an authenticator app.
 *
 * Built by Kyle Bargman, 2026-11-22, for the Northfire IRC Network.
 *
 * An account can turn on two-step sign-in (NickServ 2FA ON, then 2FA CONFIRM).
 * After that, the right password isn't enough. The person also needs the
 * 6-digit code from an authenticator app (TOTP, RFC 6238: SHA-1, 30 seconds,
 * 6 digits, which every common app uses), or one of ten single-use recovery codes.
 *
 *  - NickServ IDENTIFY with the right password is answered with "now send
 *    /msg NickServ CODE <code>"; the code must come from the same address within
 *    five minutes. SASL PLAIN works the same way: the client connects signed out,
 *    is told to send CODE, and the sign-in finishes with the code.
 *  - Client certificates (SASL EXTERNAL, or NickServ CERT) sign in without the
 *    code; a certificate is something you have, like the app.
 *  - The RPC interface (the website) takes the code as a third parameter of
 *    anope.checkCredentials; without it, or with a wrong one, the answer is
 *    error -32095.
 *  - A password reset by email (CONFIRM RESETPASS) also needs a code: add it
 *    after the reset code.
 *  - Five wrong codes in 15 minutes stop codes for that account for 15 minutes,
 *    and the owner is told, as whoever sent them knew the password.
 *  - Codes are used once (a code can't be replayed in its 30 seconds).
 *  - Services staff can turn it off for an account that lost its phone and its
 *    recovery codes (2FA RESET <nick>, privilege nickserv/twostep/reset).
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "module.h"
#include "nf_notify.h"

#include <array>
#include <random>

namespace
{
	/* Built by Kyle Bargman: SHA-1 (FIPS 180-4), only for HMAC-SHA1 in TOTP */
	std::array<uint8_t, 20> SHA1(const std::string &data)
	{
		uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
		std::string msg = data;
		const uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
		msg += static_cast<char>(0x80);
		while (msg.size() % 64 != 56)
			msg += '\0';
		for (int i = 7; i >= 0; --i)
			msg += static_cast<char>((bits >> (i * 8)) & 0xFF);

		auto rol = [](uint32_t x, int n) { return (x << n) | (x >> (32 - n)); };
		for (size_t off = 0; off < msg.size(); off += 64)
		{
			uint32_t w[80];
			for (int i = 0; i < 16; ++i)
			{
				w[i] = (static_cast<uint32_t>(static_cast<uint8_t>(msg[off + i * 4])) << 24)
					| (static_cast<uint32_t>(static_cast<uint8_t>(msg[off + i * 4 + 1])) << 16)
					| (static_cast<uint32_t>(static_cast<uint8_t>(msg[off + i * 4 + 2])) << 8)
					| static_cast<uint32_t>(static_cast<uint8_t>(msg[off + i * 4 + 3]));
			}
			for (int i = 16; i < 80; ++i)
				w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

			uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
			for (int i = 0; i < 80; ++i)
			{
				uint32_t f, k;
				if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
				else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
				else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
				else { f = b ^ c ^ d; k = 0xCA62C1D6; }
				uint32_t t = rol(a, 5) + f + e + k + w[i];
				e = d; d = c; c = rol(b, 30); b = a; a = t;
			}
			h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
		}

		std::array<uint8_t, 20> out;
		for (int i = 0; i < 5; ++i)
			for (int j = 0; j < 4; ++j)
				out[i * 4 + j] = (h[i] >> (24 - j * 8)) & 0xFF;
		return out;
	}

	/* Built by Kyle Bargman: HMAC-SHA1 (RFC 2104) */
	std::array<uint8_t, 20> HMACSHA1(const std::string &key, const std::string &data)
	{
		std::string k = key;
		if (k.size() > 64)
		{
			auto d = SHA1(k);
			k.assign(reinterpret_cast<const char *>(d.data()), d.size());
		}
		k.resize(64, '\0');
		std::string ipad(64, '\0'), opad(64, '\0');
		for (int i = 0; i < 64; ++i)
		{
			ipad[i] = static_cast<char>(k[i] ^ 0x36);
			opad[i] = static_cast<char>(k[i] ^ 0x5C);
		}
		auto inner = SHA1(ipad + data);
		return SHA1(opad + std::string(reinterpret_cast<const char *>(inner.data()), inner.size()));
	}

	const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	/* Built by Kyle Bargman: base32 (RFC 4648, no padding) as authenticator apps take it */
	Anope::string Base32Encode(const std::string &bytes)
	{
		Anope::string out;
		unsigned buf = 0;
		int bits = 0;
		for (unsigned char c : bytes)
		{
			buf = (buf << 8) | c;
			bits += 8;
			while (bits >= 5)
			{
				out.push_back(B32[(buf >> (bits - 5)) & 31]);
				bits -= 5;
			}
		}
		if (bits > 0)
			out.push_back(B32[(buf << (5 - bits)) & 31]);
		return out;
	}

	std::string Base32Decode(const Anope::string &text)
	{
		std::string out;
		unsigned buf = 0;
		int bits = 0;
		for (char c : text.str())
		{
			const char *p = strchr(B32, toupper(static_cast<unsigned char>(c)));
			if (!p || !*p)
				continue;
			buf = (buf << 5) | static_cast<unsigned>(p - B32);
			bits += 5;
			if (bits >= 8)
			{
				out.push_back(static_cast<char>((buf >> (bits - 8)) & 0xFF));
				bits -= 8;
			}
		}
		return out;
	}

	/* Built by Kyle Bargman: the 6-digit code for one 30-second step (RFC 6238 / RFC 4226) */
	unsigned TOTP(const std::string &key, uint64_t step)
	{
		std::string counter(8, '\0');
		for (int i = 7; i >= 0; --i, step >>= 8)
			counter[i] = static_cast<char>(step & 0xFF);
		auto mac = HMACSHA1(key, counter);
		int off = mac[19] & 0x0F;
		uint32_t bin = ((mac[off] & 0x7F) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
		return bin % 1000000;
	}

	/* Built by Kyle Bargman: random bytes from the system's secure source */
	std::string RandomBytes(size_t n)
	{
		static std::random_device device;
		std::string out;
		while (out.size() < n)
		{
			auto v = device();
			for (size_t i = 0; i < sizeof(v) && out.size() < n; ++i, v >>= 8)
				out.push_back(static_cast<char>(v & 0xFF));
		}
		return out;
	}

	/* Built by Kyle Bargman: a recovery code such as "k7p2-xw9d-4mqa" (no 0/o/1/l) */
	Anope::string RecoveryCode()
	{
		static const char chars[] = "abcdefghijkmnpqrstuvwxyz23456789";
		auto bytes = RandomBytes(12);
		Anope::string out;
		for (size_t i = 0; i < 12; ++i)
		{
			if (i && i % 4 == 0)
				out.push_back('-');
			out.push_back(chars[static_cast<unsigned char>(bytes[i]) % 32]);
		}
		return out;
	}

	/* Built by Kyle Bargman: a recovery code as stored (HMAC with the account's key; the code itself isn't kept) */
	Anope::string RecoveryHash(const std::string &key, Anope::string code)
	{
		code = code.lower().replace_all_cs("-", "").replace_all_cs(" ", "");
		auto mac = HMACSHA1(key, "recovery:" + code.str());
		return Anope::Hex(reinterpret_cast<const char *>(mac.data()), mac.size());
	}

	Anope::string Spaced(const Anope::string &s)
	{
		Anope::string out;
		for (size_t i = 0; i < s.length(); ++i)
		{
			if (i && i % 4 == 0)
				out.push_back(' ');
			out.push_back(s[i]);
		}
		return out;
	}

	/* Built by Kyle Bargman: a sign-in waiting for its code */
	struct Pending final
	{
		Anope::string account, address;
		time_t expires = 0;
		unsigned tries = 0;
	};

	struct Wrong final
	{
		unsigned count = 0;
		time_t first = 0, locked_until = 0;
	};

	const time_t PENDING_TIME = 300, WRONG_WINDOW = 900, WRONG_LOCK = 900;
	const unsigned WRONG_LIMIT = 5, RECOVERY_CODES = 10;
}

class NFTwoStep;

/* Built by Kyle Bargman: NickServ CODE [account] <code> */
class CommandNSCode final
	: public Command
{
public:
	std::function<void(CommandSource &, const Anope::string &, const Anope::string &)> run;

	CommandNSCode(Module *creator) : Command(creator, "nickserv/code", 1, 2)
	{
		this->SetDesc(_("Finish a two-step sign-in"));
		this->SetSyntax(_("[\037account\037] \037code\037"));
		this->AllowUnregistered(true);
		this->RequireUser(true);
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		if (params.size() > 1)
			run(source, params[0], params[1]);
		else
			run(source, "", params[0]);
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Finishes signing in to an account that uses two-step sign-in. After "
			"\002IDENTIFY\002 (or your client's SASL sign-in) accepts your password, "
			"send the 6-digit code from your authenticator app with this command "
			"within five minutes. A recovery code works too, once.\n"
			" \n"
			"Name the \037account\037 only if you signed in to more than one at once."
		));
		return true;
	}
};

/* Built by Kyle Bargman: NickServ 2FA [ON | CONFIRM | OFF | CODES | RESET] */
class CommandNS2FA final
	: public Command
{
public:
	std::function<void(CommandSource &, const std::vector<Anope::string> &)> run;

	CommandNS2FA(Module *creator) : Command(creator, "nickserv/twostep", 0, 2)
	{
		this->SetDesc(_("Turn two-step sign-in on or off"));
		this->SetSyntax("");
		this->SetSyntax(_("ON"));
		this->SetSyntax(_("CONFIRM \037code\037"));
		this->SetSyntax(_("OFF \037code\037"));
		this->SetSyntax(_("CODES \037code\037"));
		this->SetSyntax(_("RESET \037nick\037"), [](auto &source) { return source.HasPriv("nickserv/twostep/reset"); });
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		run(source, params);
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Two-step sign-in asks for a code from an authenticator app on your "
			"phone (such as Google Authenticator, Microsoft Authenticator, Aegis, "
			"2FAS, 1Password or Bitwarden) as well as your password, so a stolen "
			"password isn't enough to get into your account.\n"
			" \n"
			"\002ON\002 gives you a key to add to your app. Then \002CONFIRM\002 with "
			"the code the app shows, and you are given ten recovery codes: keep them "
			"somewhere safe, each one works once if you lose your phone.\n"
			" \n"
			"From then on, after \002IDENTIFY\002 you send \002CODE\002 with the "
			"app's code. Connecting with a client certificate (\002CERT\002, or SASL "
			"EXTERNAL) still signs you in without a code.\n"
			" \n"
			"\002OFF\002 turns it off, and \002CODES\002 makes new recovery codes; "
			"both need a current code. With no option, shows whether it is on."
		));
		if (source.HasPriv("nickserv/twostep/reset"))
			source.Reply(_(" \n\002RESET\002 turns it off for someone who has lost both their app and their recovery codes. Check who they are first."));
		return true;
	}
};

class NFTwoStep final
	: public Module
{
	CommandNSCode commandnscode;
	CommandNS2FA commandns2fa;

	/* Built by Kyle Bargman: kept with the account in the database */
	SerializableExtensibleItem<Anope::string> secret;    /* base32 key */
	SerializableExtensibleItem<Anope::string> recovery;  /* recovery code hashes, space separated */
	SerializableExtensibleItem<Anope::string> laststep;  /* the last 30-second step used */
	PrimitiveExtensibleItem<Anope::string> setup;        /* a key waiting for CONFIRM */

	std::vector<Pending> pending;
	std::map<Anope::string, Wrong, ci::less> wrong;

	bool CodesLocked(NickCore *nc)
	{
		auto it = wrong.find(nc->display);
		return it != wrong.end() && it->second.locked_until > Anope::CurTime;
	}

	/* Built by Kyle Bargman: count a wrong code; at the limit, stop codes for a while and tell the owner */
	void WrongCode(NickCore *nc, const Anope::string &address)
	{
		auto &w = wrong[nc->display];
		if (Anope::CurTime - w.first > WRONG_WINDOW)
		{
			w.count = 0;
			w.first = Anope::CurTime;
		}
		if (++w.count < WRONG_LIMIT)
			return;
		w.count = 0;
		w.locked_until = Anope::CurTime + WRONG_LOCK;
		Log(this, "alert") << "Two-step codes for " << nc->display << " are paused for " << Anope::Duration(WRONG_LOCK)
			<< " after " << WRONG_LIMIT << " wrong codes (last from " << address << ")";
		NFNotify::Owner(nc, "someone has your password",
			"Someone signed in to your account " + nc->display + " with the right password but wrong two-step codes " + Anope::ToString(WRONG_LIMIT)
			+ " times, the last from " + address + ". Your account is safe, but they know your password: change it now with /msg NickServ SET PASSWORD.");
	}

	/* Built by Kyle Bargman: a 6-digit code (each step used once), or a recovery code */
	bool CheckCode(NickCore *nc, const Anope::string &key32, Anope::string code, bool &used_recovery)
	{
		used_recovery = false;
		code = code.replace_all_cs(" ", "");
		const std::string key = Base32Decode(key32);

		if (code.length() == 6 && code.is_number_only())
		{
			const auto want = Anope::Convert<unsigned>(code, 1000000);
			const uint64_t now = static_cast<uint64_t>(Anope::CurTime) / 30;
			uint64_t last = 0;
			if (auto *l = laststep.Get(nc))
				last = Anope::Convert<uint64_t>(*l, 0);
			for (uint64_t step = now - 1; step <= now + 1; ++step)
			{
				if (step > last && TOTP(key, step) == want)
				{
					laststep.Set(nc, Anope::ToString(step));
					return true;
				}
			}
			return false;
		}

		auto *rc = recovery.Get(nc);
		if (!rc)
			return false;
		const auto hash = RecoveryHash(key, code);
		Anope::string kept;
		bool found = false;
		unsigned left = 0;
		spacesepstream sep(*rc);
		for (Anope::string h; sep.GetToken(h);)
		{
			if (!found && h.length() == hash.length() && Anope::TimingSafeEquals(h, hash))
			{
				found = true;
				continue;
			}
			kept += (kept.empty() ? "" : " ") + h;
			++left;
		}
		if (!found)
			return false;
		used_recovery = true;
		if (kept.empty())
			recovery.Unset(nc);
		else
			recovery.Set(nc, kept);
		NFNotify::Owner(nc, "a recovery code was used",
			"A two-step recovery code was used to sign in to your account " + nc->display + ". You have " + Anope::ToString(left)
			+ " left; make new ones with /msg NickServ 2FA CODES <code>.");
		return true;
	}

	/* Built by Kyle Bargman: make and store new recovery codes; returns them to show once */
	std::vector<Anope::string> NewRecoveryCodes(NickCore *nc, const Anope::string &key32)
	{
		const std::string key = Base32Decode(key32);
		std::vector<Anope::string> codes;
		Anope::string hashes;
		for (unsigned i = 0; i < RECOVERY_CODES; ++i)
		{
			codes.push_back(RecoveryCode());
			hashes += (hashes.empty() ? "" : " ") + RecoveryHash(key, codes.back());
		}
		recovery.Set(nc, hashes);
		return codes;
	}

	static void ShowRecoveryCodes(CommandSource &source, const std::vector<Anope::string> &codes)
	{
		source.Reply(_("Your recovery codes (each works once, instead of an app code). Save them now; they won't be shown again:"));
		for (size_t i = 0; i < codes.size(); i += 2)
			source.Reply("    %s    %s", codes[i].c_str(), i + 1 < codes.size() ? codes[i + 1].c_str() : "");
	}

	void Code(CommandSource &source, const Anope::string &account, const Anope::string &code)
	{
		User *u = source.GetUser();
		const Anope::string addr = u->ip.addr();

		for (auto it = pending.begin(); it != pending.end();)
			it = it->expires <= Anope::CurTime ? pending.erase(it) : std::next(it);

		std::vector<Pending>::iterator found = pending.end();
		for (auto it = pending.begin(); it != pending.end(); ++it)
		{
			if (it->address != addr || (!account.empty() && !it->account.equals_ci(account)))
				continue;
			if (found != pending.end() && !found->account.equals_ci(it->account))
			{
				source.Reply(_("You're signing in to more than one account; name the one this code is for: \002CODE \037account\037 \037code\037\002"));
				return;
			}
			found = it;
		}

		NickAlias *na = found != pending.end() ? NickAlias::Find(found->account) : nullptr;
		auto *key = na ? secret.Get(na->nc) : nullptr;
		if (!na || !key)
		{
			source.Reply(_("There is no sign-in waiting for a code from your connection. Send \002IDENTIFY\002 with your password first."));
			return;
		}
		if (CodesLocked(na->nc))
		{
			source.Reply(_("Too many wrong codes. Please wait a while and try again."));
			return;
		}

		bool used_recovery;
		if (!CheckCode(na->nc, *key, code, used_recovery))
		{
			Log(LOG_COMMAND, source, &commandnscode) << "with a wrong two-step code for " << na->nc->display;
			WrongCode(na->nc, addr);
			if (++found->tries >= WRONG_LIMIT)
			{
				pending.erase(found);
				source.Reply(_("That code isn't right. Send \002IDENTIFY\002 with your password to try again."));
			}
			else
				source.Reply(_("That code isn't right. Check the time on your phone is correct, and try the newest code."));
			return;
		}

		pending.erase(found);
		wrong.erase(na->nc->display);
		if (u->IsIdentified())
			Log(LOG_COMMAND, source, &commandnscode) << "to log out of account " << u->Account()->display;
		Log(LOG_COMMAND, source, &commandnscode) << "and identified for account " << na->nc->display << " (two-step" << (used_recovery ? ", recovery code)" : ")");
		source.Reply(_("Code accepted - you are now recognized."));
		u->Identify(na);
	}

	void TwoStep(CommandSource &source, const std::vector<Anope::string> &params)
	{
		const Anope::string what = params.empty() ? "" : params[0].upper();
		const Anope::string arg = params.size() > 1 ? params[1] : "";

		if (what == "RESET")
		{
			NickAlias *na = NickAlias::Find(arg);
			if (!source.HasPriv("nickserv/twostep/reset"))
				source.Reply(ACCESS_DENIED);
			else if (!na)
				source.Reply(NICK_X_NOT_REGISTERED, arg.c_str());
			else if (!secret.HasExt(na->nc))
				source.Reply(_("\002%s\002 doesn't use two-step sign-in."), na->nc->display.c_str());
			else
			{
				secret.Unset(na->nc);
				recovery.Unset(na->nc);
				laststep.Unset(na->nc);
				Log(LOG_ADMIN, source, &commandns2fa) << "RESET for " << na->nc->display;
				source.Reply(_("Two-step sign-in is now off for \002%s\002."), na->nc->display.c_str());
				NFNotify::Owner(na->nc, "two-step sign-in was turned off",
					"Two-step sign-in was turned off for your account " + na->nc->display + NFNotify::ByWhom(source, na->nc) + ". Turn it on again with /msg NickServ 2FA ON.");
			}
			return;
		}

		NickCore *nc = source.GetAccount();
		if (!nc)
		{
			source.Reply(NICK_IDENTIFY_REQUIRED);
			return;
		}
		auto *key = secret.Get(nc);

		if (what.empty() || what == "STATUS")
		{
			if (!key)
			{
				source.Reply(_("Two-step sign-in is \002off\002. Turn it on with \002%s ON\002."), source.command.c_str());
				return;
			}
			unsigned left = 0;
			if (auto *rc = recovery.Get(nc))
			{
				spacesepstream sep(*rc);
				for (Anope::string h; sep.GetToken(h);)
					++left;
			}
			source.Reply(_("Two-step sign-in is \002on\002. You have %u recovery code(s) left."), left);
			return;
		}

		if (what == "ON")
		{
			if (key)
			{
				source.Reply(_("Two-step sign-in is already on."));
				return;
			}
			const Anope::string fresh = Base32Encode(RandomBytes(20));
			setup.Set(nc, fresh);
			const Anope::string label = Anope::string("Northfire:") + nc->display;
			source.Reply(_("Add this key to your authenticator app (choose \"enter a setup key\", time-based):"));
			source.Reply("    \002%s\002", Spaced(fresh).c_str());
			source.Reply(_("Or, if your app takes a link: otpauth://totp/%s?secret=%s&issuer=Northfire"), label.c_str(), fresh.c_str());
			source.Reply(_("Then send \002%s CONFIRM \037code\037\002 with the 6-digit code the app shows."), source.command.c_str());
			return;
		}

		if (what == "CONFIRM")
		{
			auto *fresh = setup.Get(nc);
			if (key)
				source.Reply(_("Two-step sign-in is already on."));
			else if (!fresh)
				source.Reply(_("Start with \002%s ON\002."), source.command.c_str());
			else if (arg.empty())
				this->commandns2fa.OnSyntaxError(source, "CONFIRM");
			else
			{
				const std::string k = Base32Decode(*fresh);
				const uint64_t now = static_cast<uint64_t>(Anope::CurTime) / 30;
				const auto want = Anope::Convert<unsigned>(arg.replace_all_cs(" ", ""), 1000000);
				uint64_t used = 0;
				for (uint64_t step = now - 1; step <= now + 1 && !used; ++step)
				{
					if (TOTP(k, step) == want)
						used = step;
				}
				if (!used)
				{
					source.Reply(_("That code isn't right. Check the key was entered correctly and the time on your phone is right, then try the newest code."));
					return;
				}
				secret.Set(nc, *fresh);
				laststep.Set(nc, Anope::ToString(used));
				setup.Unset(nc);
				Log(LOG_COMMAND, source, &commandns2fa) << "to turn on two-step sign-in";
				source.Reply(_("Two-step sign-in is now \002on\002."));
				ShowRecoveryCodes(source, NewRecoveryCodes(nc, *secret.Get(nc)));
				source.Reply(_("From now on, send \002CODE \037code\037\002 after \002IDENTIFY\002. Client certificate sign-ins don't need a code."));
				NFNotify::Owner(nc, "two-step sign-in was turned on", "Two-step sign-in was turned on for your account " + nc->display + ".");
			}
			return;
		}

		if (what == "OFF" || what == "CODES")
		{
			bool used_recovery;
			if (!key)
				source.Reply(_("Two-step sign-in is off."));
			else if (arg.empty())
				this->commandns2fa.OnSyntaxError(source, what);
			else if (CodesLocked(nc))
				source.Reply(_("Too many wrong codes. Please wait a while and try again."));
			else if (!CheckCode(nc, *key, arg, used_recovery))
			{
				WrongCode(nc, source.GetUser() ? source.GetUser()->ip.addr() : "?");
				source.Reply(_("That code isn't right."));
			}
			else if (what == "OFF")
			{
				secret.Unset(nc);
				recovery.Unset(nc);
				laststep.Unset(nc);
				Log(LOG_COMMAND, source, &commandns2fa) << "to turn off two-step sign-in";
				source.Reply(_("Two-step sign-in is now \002off\002."));
				NFNotify::Owner(nc, "two-step sign-in was turned off", "Two-step sign-in was turned off for your account " + nc->display + ".");
			}
			else
			{
				Log(LOG_COMMAND, source, &commandns2fa) << "to make new recovery codes";
				ShowRecoveryCodes(source, NewRecoveryCodes(nc, *key));
				source.Reply(_("Your old recovery codes no longer work."));
			}
			return;
		}

		this->commandns2fa.OnSyntaxError(source, what);
	}

public:
	NFTwoStep(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
		, commandnscode(this)
		, commandns2fa(this)
		, secret(this, "nf_twostep_secret")
		, recovery(this, "nf_twostep_recovery")
		, laststep(this, "nf_twostep_last")
		, setup(this, "nf_twostep_setup")
	{
		this->SetAuthor("Kyle Bargman");
		this->SetVersion("1.0");
		commandnscode.run = [this](CommandSource &source, const Anope::string &account, const Anope::string &code) { Code(source, account, code); };
		commandns2fa.run = [this](CommandSource &source, const std::vector<Anope::string> &params) { TwoStep(source, params); };
	}

	EventReturn OnIdentifySecondFactor(IdentifyRequest *req, NickAlias *na) override
	{
		auto *key = secret.Get(na->nc);
		if (!key)
			return EVENT_CONTINUE;

		if (CodesLocked(na->nc))
		{
			req->Refuse("second-factor", _("Too many wrong two-step codes. Please wait a while and try again."));
			return EVENT_STOP;
		}

		/* Sent with the password (the website) */
		if (!req->GetSecondFactor().empty())
		{
			bool used_recovery;
			if (CheckCode(na->nc, *key, req->GetSecondFactor(), used_recovery))
			{
				wrong.erase(na->nc->display);
				return EVENT_CONTINUE;
			}
			WrongCode(na->nc, req->GetAddress());
			req->Refuse("second-factor", _("That two-step code isn't right."));
			return EVENT_STOP;
		}

		/* Otherwise wait for NickServ CODE from the same address */
		Pending p;
		p.account = na->nick;
		p.address = req->GetAddress();
		p.expires = Anope::CurTime + PENDING_TIME;
		for (auto it = pending.begin(); it != pending.end();)
			it = (it->address == p.address && it->account.equals_ci(p.account)) || it->expires <= Anope::CurTime ? pending.erase(it) : std::next(it);
		pending.push_back(p);
		req->Refuse("second-factor", _("Password accepted. This account uses two-step sign-in: now send \002/msg NickServ CODE \037code\037\002 with the 6-digit code from your authenticator app."));
		return EVENT_STOP;
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) override
	{
		/* Built by Kyle Bargman: an emailed reset code alone mustn't get round two-step sign-in.
		 * CONFIRM RESETPASS [nick] <reset code> <app code> */
		if (command->name != "nickserv/confirm/resetpass" || params.empty())
			return EVENT_CONTINUE;

		/* The command takes at most two parameters, so the app code is folded into the last one */
		Anope::string nick, rest;
		if (params.size() > 1)
		{
			nick = params[0];
			rest = params[1];
		}
		else
		{
			nick = source.GetNick();
			rest = params[0];
		}
		auto *na = NickAlias::Find(nick);
		if (!na && params.size() > 1)
		{
			/* "CONFIRM RESETPASS <reset code> <app code>" from the account's own nick */
			na = NickAlias::Find(source.GetNick());
			nick = source.GetNick();
			rest = params[0] + " " + params[1];
		}
		auto *key = na ? secret.Get(na->nc) : nullptr;
		if (!key)
			return EVENT_CONTINUE;

		Anope::string resetcode, appcode;
		spacesepstream sep(rest);
		sep.GetToken(resetcode);
		appcode = sep.GetRemaining();
		if (appcode.empty())
		{
			source.Reply(_("\002%s\002 uses two-step sign-in: add the code from your authenticator app (or a recovery code) after the reset code."), na->nc->display.c_str());
			return EVENT_STOP;
		}
		if (CodesLocked(na->nc))
		{
			source.Reply(_("Too many wrong codes. Please wait a while and try again."));
			return EVENT_STOP;
		}
		bool used_recovery;
		if (!CheckCode(na->nc, *key, appcode, used_recovery))
		{
			WrongCode(na->nc, source.GetUser() ? source.GetUser()->ip.addr() : "?");
			source.Reply(_("That two-step code isn't right."));
			return EVENT_STOP;
		}
		params.clear();
		params.push_back(nick);
		params.push_back(resetcode);
		return EVENT_CONTINUE;
	}

	void OnUserConnect(User *u, bool &exempt) override
	{
		/* Built by Kyle Bargman: SASL accepted the password and is waiting for the code */
		for (const auto &p : pending)
		{
			if (p.address == u->ip.addr() && p.expires > Anope::CurTime && Anope::CurTime - (p.expires - PENDING_TIME) < 60)
			{
				auto *ns = Config->GetClient("NickServ");
				if (ns)
					u->SendMessage(ns, _("Your client's password was accepted for \002%s\002, which uses two-step sign-in: send \002/msg NickServ CODE \037code\037\002 to finish signing in."), p.account.c_str());
				break;
			}
		}
	}

	void OnDelCore(NickCore *nc) override
	{
		wrong.erase(nc->display);
	}
};

MODULE_INIT(NFTwoStep)
