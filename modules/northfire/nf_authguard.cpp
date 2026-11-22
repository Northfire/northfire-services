/*
 * Northfire Services: nf_authguard - limits password guessing.
 *
 * Built by Kyle Bargman, 2026-11-22, for the Northfire IRC Network.
 *
 * Every password sign-in (NickServ IDENTIFY, SASL PLAIN, RECOVER, GROUP,
 * webcpanel and the RPC interface) goes through the core's OnIdentifyGate
 * and OnIdentifyResult events. This module counts failures:
 *
 *  - per address (IPv4 address, IPv6 /64): after ip_limit failures within
 *    ip_window the address may not sign in for ip_lock; each lockout in a row
 *    doubles that, up to ip_lock_max.
 *  - per account (from every address): after account_limit failures within
 *    account_window the account is locked for account_lock, except from
 *    addresses that have signed in to it before (so guessing can't lock the
 *    owner out).
 *  - per account and address together: ip_limit failures within ip_window
 *    lock that pair, always (so a trusted address is no way round the limit).
 *
 * Addresses an account has signed in from before skip the address and account
 * lockouts (shared addresses such as a bouncer, or the owner's own), but never
 * the account+address one.
 *
 * A locked-out attempt fails even with the right password and is not counted.
 * Staff are alerted (log category "nf_authguard/alert"); the owner is told how
 * many failed attempts there were the next time they sign in. OperServ
 * AUTHGUARD lists and clears lockouts.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "module.h"
#include "nf_notify.h"

#include <map>

namespace
{
	using NFNotify::AddressKey;

	/* Built by Kyle Bargman: failure count for one address or account */
	struct Strikes final
	{
		unsigned count = 0;
		time_t first = 0;
		time_t last = 0;
		time_t locked_until = 0;
		unsigned lockouts = 0;
	};

	struct Limits final
	{
		unsigned limit = 5;
		time_t window = 900;
		time_t lock = 900;
		time_t lock_max = 86400;
	};

	/* Built by Kyle Bargman: an address shown to the account owner (last part hidden) */
	Anope::string ShownAddress(const Anope::string &key)
	{
		if (key.find(':') != Anope::string::npos || key == "unknown")
			return key;
		auto dot = key.rfind('.');
		return dot == Anope::string::npos ? key : key.substr(0, dot) + ".*";
	}
}

/* Built by Kyle Bargman: OperServ AUTHGUARD LIST | CLEAR <address|account|ALL> */
class CommandOSAuthGuard final
	: public Command
{
public:
	std::function<void(CommandSource &)> list;
	std::function<unsigned(const Anope::string &)> clear;

	CommandOSAuthGuard(Module *creator) : Command(creator, "operserv/authguard", 1, 2)
	{
		this->SetDesc(_("List or clear sign-in lockouts"));
		this->SetSyntax(_("LIST"));
		this->SetSyntax(_("CLEAR {\037address\037 | \037account\037 | ALL}"));
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		const Anope::string &cmd = params[0];
		if (cmd.equals_ci("LIST"))
		{
			list(source);
			return;
		}
		if (cmd.equals_ci("CLEAR") && params.size() > 1)
		{
			Log(LOG_ADMIN, source, this) << "CLEAR " << params[1];
			unsigned n = clear(params[1]);
			if (n)
				source.Reply(_("Cleared %u lockout record(s) for \002%s\002."), n, params[1].c_str());
			else
				source.Reply(_("No lockout records for \002%s\002."), params[1].c_str());
			return;
		}
		this->OnSyntaxError(source, cmd);
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Services count failed password sign-ins per address and per "
			"account, and lock them out for a while after too many.\n"
			" \n"
			"\002LIST\002 shows the addresses and accounts that are locked "
			"out now, or have recent failures.\n"
			" \n"
			"\002CLEAR\002 forgets the failures and lockout for an address "
			"(IPv6 addresses are counted by /64), an account, or \002ALL\002."
		));
		return true;
	}
};

class NFAuthGuard final
	: public Module
{
	CommandOSAuthGuard commandosauthguard;

	/* Built by Kyle Bargman: kept with the account in the database */
	SerializableExtensibleItem<Anope::string> trusted;  /* "key=time key=time ..." */
	SerializableExtensibleItem<Anope::string> missed;   /* "count key time" */

	std::map<Anope::string, Strikes> ips;
	std::map<Anope::string, Strikes, ci::less> accounts;
	std::map<Anope::string, Strikes, ci::less> pairs;  /* "account address" */

	Limits ip_limits, account_limits;
	unsigned trusted_max = 5;
	time_t trusted_days = 90;
	time_t last_prune = 0;

	/* Built by Kyle Bargman: is this address one the account has signed in from? */
	bool IsTrusted(NickCore *nc, const Anope::string &key)
	{
		auto *t = trusted.Get(nc);
		if (!t)
			return false;
		spacesepstream sep(*t);
		for (Anope::string entry; sep.GetToken(entry);)
		{
			auto eq = entry.rfind('=');
			if (eq == Anope::string::npos)
				continue;
			auto when = Anope::Convert<time_t>(entry.substr(eq + 1), 0);
			if (entry.substr(0, eq) == key && Anope::CurTime - when < trusted_days * 86400)
				return true;
		}
		return false;
	}

	/* Built by Kyle Bargman: remember the address of a good sign-in (newest first) */
	void Trust(NickCore *nc, const Anope::string &key)
	{
		Anope::string out = key + "=" + Anope::ToString(Anope::CurTime);
		unsigned kept = 1;
		if (auto *t = trusted.Get(nc))
		{
			spacesepstream sep(*t);
			for (Anope::string entry; sep.GetToken(entry) && kept < trusted_max;)
			{
				auto eq = entry.rfind('=');
				if (eq == Anope::string::npos || entry.substr(0, eq) == key)
					continue;
				if (Anope::CurTime - Anope::Convert<time_t>(entry.substr(eq + 1), 0) >= trusted_days * 86400)
					continue;
				out += " " + entry;
				++kept;
			}
		}
		trusted.Set(nc, out);
	}

	/* Built by Kyle Bargman: count one failure; returns the lockout length if this one locks */
	static time_t Strike(Strikes &s, const Limits &l)
	{
		if (Anope::CurTime - s.first > l.window)
		{
			s.count = 0;
			s.first = Anope::CurTime;
		}
		s.last = Anope::CurTime;
		if (++s.count < l.limit)
			return 0;

		/* Lockouts in a row double, forgotten after a quiet day */
		if (Anope::CurTime - s.locked_until > 86400)
			s.lockouts = 0;
		time_t len = l.lock;
		for (unsigned i = 0; i < s.lockouts && len < l.lock_max; ++i)
			len *= 2;
		len = std::min(len, l.lock_max);
		++s.lockouts;
		s.count = 0;
		s.locked_until = Anope::CurTime + len;
		return len;
	}

	/* Built by Kyle Bargman: drop records nobody needs any more */
	void Prune()
	{
		if (Anope::CurTime - last_prune < 300)
			return;
		last_prune = Anope::CurTime;
		auto stale = [this](const Strikes &s) {
			return s.locked_until < Anope::CurTime - 86400 && Anope::CurTime - s.last > std::max(ip_limits.window, account_limits.window);
		};
		for (auto it = ips.begin(); it != ips.end();)
			it = stale(it->second) ? ips.erase(it) : std::next(it);
		for (auto it = accounts.begin(); it != accounts.end();)
			it = stale(it->second) ? accounts.erase(it) : std::next(it);
		for (auto it = pairs.begin(); it != pairs.end();)
			it = stale(it->second) ? pairs.erase(it) : std::next(it);
	}

	static Limits ReadLimits(const Configuration::Block &block, const Anope::string &prefix, unsigned limit, const char *window, const char *lock, const char *lock_max)
	{
		Limits l;
		l.limit = std::max(1u, block.Get<unsigned>(prefix + "_limit", Anope::ToString(limit)));
		l.window = std::max<time_t>(1, block.Get<time_t>(prefix + "_window", window));
		l.lock = std::max<time_t>(1, block.Get<time_t>(prefix + "_lock", lock));
		l.lock_max = std::max(l.lock, block.Get<time_t>(prefix + "_lock_max", lock_max));
		return l;
	}

	void ListLockouts(CommandSource &source)
	{
		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Type")).AddColumn(_("Name")).AddColumn(_("Failures")).AddColumn(_("Locked for"));
		auto add = [&list](const char *type, const Anope::string &name, const Strikes &s) {
			bool locked = s.locked_until > Anope::CurTime;
			if (!locked && Anope::CurTime - s.last > 86400)
				return;
			ListFormatter::ListEntry entry;
			entry["Type"] = type;
			entry["Name"] = name;
			entry["Failures"] = Anope::ToString(s.count);
			entry["Locked for"] = locked ? Anope::Duration(s.locked_until - Anope::CurTime) : "-";
			list.AddEntry(entry);
		};
		for (const auto &[name, s] : ips)
			add("address", name, s);
		for (const auto &[name, s] : accounts)
			add("account", name, s);
		for (const auto &[name, s] : pairs)
			add("account+address", name, s);

		if (list.IsEmpty())
		{
			source.Reply(_("There are no recent failed sign-ins."));
			return;
		}
		list.SendTo(source);
	}

	unsigned ClearLockouts(const Anope::string &what)
	{
		if (what.equals_ci("ALL"))
		{
			unsigned n = ips.size() + accounts.size() + pairs.size();
			ips.clear();
			accounts.clear();
			pairs.clear();
			return n;
		}
		unsigned n = ips.erase(AddressKey(what)) + ips.erase(what);
		auto *na = NickAlias::Find(what);
		const Anope::string account = na ? na->nc->display : what, key = AddressKey(what);
		n += accounts.erase(account);
		for (auto it = pairs.begin(); it != pairs.end();)
		{
			auto sp = it->first.find(' ');
			bool match = it->first.substr(0, sp).equals_ci(account) || it->first.substr(sp + 1) == key;
			if (match)
			{
				it = pairs.erase(it);
				++n;
			}
			else
				++it;
		}
		return n;
	}

public:
	NFAuthGuard(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
		, commandosauthguard(this)
		, trusted(this, "nf_authguard_trusted")
		, missed(this, "nf_authguard_missed")
	{
		this->SetAuthor("Kyle Bargman");
		this->SetVersion("1.0");
		commandosauthguard.list = [this](CommandSource &source) { ListLockouts(source); };
		commandosauthguard.clear = [this](const Anope::string &what) { return ClearLockouts(what); };
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &block = conf.GetModule(this);
		ip_limits = ReadLimits(block, "ip", 5, "15m", "15m", "1d");
		account_limits = ReadLimits(block, "account", 20, "1h", "30m", "6h");
		trusted_max = std::max(1u, block.Get<unsigned>("trusted_max", "5"));
		trusted_days = std::max<time_t>(1, block.Get<time_t>("trusted_days", "90"));
	}

	EventReturn OnIdentifyGate(IdentifyRequest *req) override
	{
		const auto key = AddressKey(req->GetAddress());
		auto locked = [](const auto &map, const Anope::string &k) {
			auto it = map.find(k);
			return it != map.end() && it->second.locked_until > Anope::CurTime;
		};

		auto *na = NickAlias::Find(req->GetAccount());
		bool refuse;
		if (!na)
			refuse = locked(ips, key);
		else if (locked(pairs, na->nc->display + " " + key))
			refuse = true;
		else if (IsTrusted(na->nc, key))
			refuse = false;
		else
			refuse = locked(ips, key) || locked(accounts, na->nc->display);
		if (!refuse)
			return EVENT_CONTINUE;
		req->Refuse("locked");
		return EVENT_STOP;
	}

	void OnIdentifyResult(IdentifyRequest *req) override
	{
		Prune();
		if (req->IsBlocked())
			return;

		const auto key = AddressKey(req->GetAddress());
		auto *na = NickAlias::Find(req->GetAccount());

		if (req->IsSuccess())
		{
			if (na)
			{
				Trust(na->nc, key);
				accounts.erase(na->nc->display);
				pairs.erase(na->nc->display + " " + key);
			}
			return;
		}

		/* An address that has signed in to this account isn't counted against
		 * everyone else using it (a bouncer); the pair below still is. */
		if (!na || !IsTrusted(na->nc, key))
		{
			if (time_t len = Strike(ips[key], ip_limits))
				Log(this, "alert") << "Address " << key << " is locked out of signing in for " << Anope::Duration(len)
					<< " after " << ip_limits.limit << " failed attempts (last tried: " << req->GetAccount() << ")";
		}

		if (!na)
			return;

		if (time_t len = Strike(pairs[na->nc->display + " " + key], ip_limits))
			Log(this, "alert") << "Account " << na->nc->display << " is locked from " << key << " for " << Anope::Duration(len)
				<< " after " << ip_limits.limit << " failed attempts";

		auto &s = accounts[na->nc->display];
		if (time_t len = Strike(s, account_limits))
		{
			Log(this, "alert") << "Account " << na->nc->display << " is locked for " << Anope::Duration(len)
				<< " (except from addresses it has used) after " << account_limits.limit << " failed attempts";
			/* Built by Kyle Bargman: someone is guessing this account's password from many places */
			NFNotify::Owner(na->nc, "someone is guessing your password",
				"There were " + Anope::ToString(account_limits.limit) + " failed sign-in attempts on your account " + na->nc->display
				+ " within " + Anope::Duration(account_limits.window) + ", the last from " + ShownAddress(key) + ". Signing in is paused for "
				+ Anope::Duration(len) + ", except from addresses you have used before. If you use a weak password, change it with /msg NickServ SET PASSWORD.");
		}

		/* For the owner's next sign-in */
		unsigned count = 0;
		if (auto *m = missed.Get(na->nc))
		{
			spacesepstream sep(*m);
			Anope::string first;
			if (sep.GetToken(first))
				count = Anope::Convert<unsigned>(first, 0);
		}
		missed.Set(na->nc, Anope::ToString(count + 1) + " " + key + " " + Anope::ToString(Anope::CurTime));
	}

	void OnNickIdentify(User *u) override
	{
		/* Built by Kyle Bargman: every finished sign-in (two-step codes and certificates
		 * too, but not registering) makes its address one the owner uses */
		auto *na = NickAlias::Find(u->nick);
		if (na && na->nc == u->Account() && na->registered == Anope::CurTime)
			return;  /* just registered */
		if (u->Account())
			Trust(u->Account(), AddressKey(u->ip.addr()));
	}

	void OnUserLogin(User *u) override
	{
		auto *nc = u->Account();
		auto *m = nc ? missed.Get(nc) : nullptr;
		if (!m)
			return;

		spacesepstream sep(*m);
		Anope::string count, key, when;
		sep.GetToken(count);
		sep.GetToken(key);
		sep.GetToken(when);
		missed.Unset(nc);

		auto *ns = Config->GetClient("NickServ");
		auto n = Anope::Convert<unsigned>(count, 0);
		if (!n)
			return;
		u->SendMessage(ns, _("There %s \002%u\002 failed sign-in %s on your account since you last signed in; the last was from %s, %s."),
			n == 1 ? "was" : "were", n, n == 1 ? "attempt" : "attempts", ShownAddress(key).c_str(),
			Anope::strftime(Anope::Convert<time_t>(when, 0), nc, true).c_str());
		u->SendMessage(ns, _("If that wasn't you, choose a stronger password with \002/msg NickServ SET PASSWORD\002."));
	}
};

MODULE_INIT(NFAuthGuard)
