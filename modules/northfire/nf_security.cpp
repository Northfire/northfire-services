/*
 * Northfire Services: nf_security - security notices, and where you're signed in.
 *
 * Built by Kyle Bargman, 2026-11-22, for the Northfire IRC Network.
 *
 * Security notices: when an account's password, email address or client
 * certificates change, or someone signs in with an emailed password-reset code,
 * the owner is told by NickServ notice, memo and email (see nf_notify.h). After an
 * email change the old address is told as well, so a stolen account can't be
 * quietly moved to a new address.
 *
 * NickServ SESSIONS lists every connection signed in to your account, and the
 * addresses you have signed in from lately. NickServ SIGNOUT signs out your other
 * connections (one, or ALL), and ALL also forgets the remembered addresses, so
 * someone who had your password loses nf_authguard's trust as well.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "module.h"
#include "modules/nickserv/cert.h"
#include "modules/nickserv/service.h"
#include "nf_notify.h"

namespace
{
	/* Built by Kyle Bargman: what an account looked like before a command ran */
	struct Snapshot final
	{
		Serialize::Reference<NickCore> nc;
		Anope::string pass, email;
		std::set<Anope::string> certs;
	};

	std::set<Anope::string> Certs(NickCore *nc)
	{
		std::set<Anope::string> out;
		auto *cl = nc->GetExt<NickServ::CertList>(NICKSERV_CERT_EXT);
		for (unsigned i = 0; cl && i < cl->GetCertCount(); ++i)
			out.insert(cl->GetCert(i)->fingerprint);
		return out;
	}

	Anope::string ShortPrint(const Anope::string &fp)
	{
		return fp.length() > 16 ? fp.substr(0, 16) + "..." : fp;
	}

	/* Built by Kyle Bargman: the sign-in address part of nf_authguard's "key=time ..." */
	Anope::string AddressOf(const Anope::string &entry)
	{
		auto eq = entry.rfind('=');
		return eq == Anope::string::npos ? entry : entry.substr(0, eq);
	}

	/* Built by Kyle Bargman: sign one connection out of its account (as NickServ LOGOUT does) */
	void SignOut(User *u, BotInfo *ns)
	{
		u->super_admin = false;
		u->SendMessage(ns, _("You have been signed out of your account from another connection."));
		IRCD->SendLogout(u);
		u->RemoveMode(ns, "REGISTERED");
		u->Logout();
		FOREACH_MOD(OnNickLogout, (u));
		if (NickServ::service)
			NickServ::service->Validate(u);
	}
}

/* Built by Kyle Bargman: NickServ SESSIONS */
class CommandNSSessions final
	: public Command
{
public:
	CommandNSSessions(Module *creator) : Command(creator, "nickserv/sessions", 0, 0)
	{
		this->SetDesc(_("Show where you're signed in"));
		this->RequireUser(true);
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		NickCore *nc = source.GetAccount();
		User *me = source.GetUser();

		source.Reply(_("Connections signed in to \002%s\002:"), nc->display.c_str());
		unsigned n = 0;
		for (auto *u : nc->users)
		{
			source.Reply(_("%2u. \002%s\002 (%s@%s) connected %s ago%s%s"), ++n, u->nick.c_str(), u->GetIdent().c_str(),
				u->ip.addr().c_str(), Anope::Duration(Anope::CurTime - u->signon, nc).c_str(),
				u->IsSecurelyConnected() ? ", TLS" : ", \002not TLS\002", u == me ? " (this connection)" : "");
		}

		if (auto *trusted = nc->GetExt<Anope::string>("nf_authguard_trusted"))
		{
			source.Reply(" ");
			source.Reply(_("Addresses you've signed in from recently:"));
			spacesepstream sep(*trusted);
			for (Anope::string entry; sep.GetToken(entry);)
			{
				auto eq = entry.rfind('=');
				auto when = eq == Anope::string::npos ? 0 : Anope::Convert<time_t>(entry.substr(eq + 1), 0);
				source.Reply("    %s (%s)", AddressOf(entry).c_str(), when ? Anope::strftime(when, nc, true).c_str() : "?");
			}
		}

		source.Reply(" ");
		source.Reply(_("If you don't recognise one of these, use \002%s ALL\002 and change your password."),
			source.service->GetQueryCommand("nickserv/signout").c_str());
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Lists every connection that is signed in to your account (its nick, "
			"address, how long it has been connected, and whether it uses TLS), and "
			"the addresses you have signed in from lately."
		));
		return true;
	}
};

/* Built by Kyle Bargman: NickServ SIGNOUT {nick | ALL} */
class CommandNSSignout final
	: public Command
{
public:
	CommandNSSignout(Module *creator) : Command(creator, "nickserv/signout", 1, 1)
	{
		this->SetDesc(_("Sign out your other connections"));
		this->SetSyntax(_("{\037nick\037 | ALL}"));
		this->RequireUser(true);
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		NickCore *nc = source.GetAccount();
		User *me = source.GetUser();
		auto *ns = Config->GetClient("NickServ");
		const bool all = params[0].equals_ci("ALL");

		std::vector<User *> targets;
		for (auto *u : nc->users)
		{
			if (u != me && (all || u->nick.equals_ci(params[0])))
				targets.push_back(u);
		}

		if (!all && targets.empty())
		{
			source.Reply(_("\002%s\002 isn't another connection signed in to your account. See \002%s\002."),
				params[0].c_str(), source.service->GetQueryCommand("nickserv/sessions").c_str());
			return;
		}

		for (auto *u : targets)
			SignOut(u, ns);

		if (all)
		{
			/* Forget the remembered sign-in addresses, except this connection's */
			const Anope::string mine = NFNotify::AddressKey(me->ip.addr());
			if (auto *trusted = nc->GetExt<Anope::string>("nf_authguard_trusted"))
			{
				Anope::string kept;
				spacesepstream sep(*trusted);
				for (Anope::string entry; sep.GetToken(entry);)
				{
					if (AddressOf(entry) == mine)
						kept = entry;
				}
				if (kept.empty())
					nc->Shrink<Anope::string>("nf_authguard_trusted");
				else
					nc->Extend<Anope::string>("nf_authguard_trusted", kept);
			}
		}

		Log(LOG_COMMAND, source, this) << "to sign out " << targets.size() << " other connection(s)" << (all ? " and forget remembered addresses" : "");
		source.Reply(targets.size(), N_("Signed out \002%zu\002 other connection.", "Signed out \002%zu\002 other connections."), targets.size());
		if (all)
			source.Reply(_("Addresses you'd signed in from before are forgotten, except this one. If someone else knew your password, change it now with \002%s\002."),
				source.service->GetQueryCommand("nickserv/set/password").c_str());

		if (!targets.empty() || all)
			NFNotify::Owner(nc, "connections signed out", Anope::string(all ? "All other connections to" : "A connection to") + " your account "
				+ nc->display + (all ? " were" : " was") + " signed out from " + me->ip.addr() + (all ? ", and its remembered sign-in addresses forgotten." : "."));
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Signs out another connection that is signed in to your account (see "
			"\002SESSIONS\002), or \002ALL\002 of them except this one.\n"
			" \n"
			"\002ALL\002 also forgets the addresses you have signed in from before, "
			"so they lose their exemption from the sign-in lockouts. If you think "
			"someone else knows your password, use \002SIGNOUT ALL\002 and then "
			"change your password."
		));
		return true;
	}
};

class NFSecurity final
	: public Module
{
	CommandNSSessions commandnssessions;
	CommandNSSignout commandnssignout;

	/* Built by Kyle Bargman: the command running now, and its accounts as they were */
	Command *running = nullptr;
	std::vector<Snapshot> before;
	Reference<User> user;
	Serialize::Reference<NickCore> user_account;

	static bool Watched(const Anope::string &name)
	{
		/* Signing in can re-hash a password (an upgrade, not a change), so those are skipped */
		static const std::set<Anope::string> skip = {
			"nickserv/identify", "nickserv/group", "nickserv/recover", "nickserv/register", "nickserv/logout",
		};
		return name.find("nickserv/") == 0 && !skip.count(name);
	}

	void Take(NickCore *nc)
	{
		if (!nc)
			return;
		for (const auto &s : before)
		{
			if (s.nc == nc)
				return;
		}
		Snapshot s;
		s.nc = nc;
		s.pass = nc->pass;
		s.email = nc->email;
		s.certs = Certs(nc);
		before.push_back(s);
	}

public:
	NFSecurity(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
		, commandnssessions(this)
		, commandnssignout(this)
	{
		this->SetAuthor("Kyle Bargman");
		this->SetVersion("1.0");
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) override
	{
		running = nullptr;
		before.clear();
		if (!Watched(command->name))
			return EVENT_CONTINUE;

		running = command;
		user = source.GetUser();
		user_account = source.GetUser() ? source.GetUser()->Account() : nullptr;
		Take(source.GetAccount());
		for (const auto &p : params)
		{
			auto *na = NickAlias::Find(p[0] == '@' ? p.substr(1) : p);
			if (na)
				Take(na->nc);
		}
		return EVENT_CONTINUE;
	}

	void OnPostCommand(CommandSource &source, Command *command, const std::vector<Anope::string> &params) override
	{
		if (command != running)
			return;
		running = nullptr;
		auto snaps = std::move(before);
		before.clear();

		for (auto &s : snaps)
		{
			NickCore *nc = s.nc;
			if (!nc)
				continue;  /* dropped */
			const auto by = NFNotify::ByWhom(source, nc);

			if (nc->pass != s.pass)
			{
				Log(this) << "Password changed for " << nc->display << by;
				NFNotify::Owner(nc, "your password was changed", "The password for your account " + nc->display + " was changed" + by + ".");
			}
			if (!nc->email.equals_ci(s.email))
			{
				Log(this) << "Email changed for " << nc->display << by;
				NFNotify::Owner(nc, "your email address was changed",
					"The email address on your account " + nc->display + " was changed from " + (s.email.empty() ? "none" : s.email)
					+ " to " + (nc->email.empty() ? "none" : nc->email) + by + ".", s.email);
			}

			auto now = Certs(nc);
			for (const auto &fp : now)
			{
				if (!s.certs.count(fp))
					NFNotify::Owner(nc, "a client certificate was added",
						"A client certificate (" + ShortPrint(fp) + ") was added to your account " + nc->display + by + ". Connections using it are signed in without a password.");
			}
			for (const auto &fp : s.certs)
			{
				if (!now.count(fp))
					NFNotify::Owner(nc, "a client certificate was removed",
						"A client certificate (" + ShortPrint(fp) + ") was removed from your account " + nc->display + by + ".");
			}
		}

		/* An emailed reset code signs the person in without a password */
		if (command->name == "nickserv/confirm/resetpass" && user && user->Account() && user->Account() != static_cast<NickCore *>(user_account))
		{
			NickCore *nc = user->Account();
			NFNotify::Owner(nc, "a password reset code was used",
				"Someone signed in to your account " + nc->display + " from " + user->ip.addr() + " with a password reset code sent to your email address.");
		}
	}
};

MODULE_INIT(NFSecurity)
