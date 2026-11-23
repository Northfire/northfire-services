/*
 * Northfire Services: nf_forum - the forums and IRC, together.
 *
 * Built by Kyle Bargman, 2026-11-22, for the Northfire IRC Network.
 *
 * One-click chat: the forum, for a member it has already signed in (with the
 * password, and the two-step code if the account uses one), asks for a one-time
 * login code (RPC northfire.loginToken). The browser hands it to the web chat,
 * which signs in with it as the password (SASL PLAIN or IDENTIFY), prefixed
 * "nftoken:". A code works once, for one account, for 60 seconds, and counts as
 * the second step (the forum checked it). Codes live in memory only.
 *
 * And for the forum, through the relay (nf-anope-rpcd):
 *   northfire.account  <account>          the primary nick (display), suspended or not
 *   northfire.announce <#channel> <text>  a line in a channel (only those in "announce")
 *   northfire.notify   <account> <text>   a notice to each of the account's connections,
 *                                         or a memo if none is online
 *   northfire.online   <#channel>         the nicks in a public channel
 * NickServ FORUM [nick] gives the link to a member's forum page.
 *
 *   module { name = "nf_forum"; forum_url = "https://northfire.dev/forums"; announce = "#Northfire"; }
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "module.h"
#include "modules/rpc.h"
#include "modules/memoserv/service.h"

namespace
{
	const Anope::string TOKEN_PREFIX = "nftoken:";
	const time_t TOKEN_TIME = 60;

	enum
	{
		ERR_NO_ACCOUNT = RPC::ERR_CUSTOM_START,
		ERR_SUSPENDED = RPC::ERR_CUSTOM_START + 1,
		ERR_NOT_ALLOWED = RPC::ERR_CUSTOM_START + 2,
		ERR_NO_CHANNEL = RPC::ERR_CUSTOM_START + 3,
	};

	/* Built by Kyle Bargman: one outstanding login code */
	struct Token final
	{
		Anope::string account;  /* lower case */
		Anope::string code;
		time_t expires;
	};

	std::vector<Token> tokens;
	Anope::string forum_url = "https://northfire.dev/forums";
	std::vector<Anope::string> announce_channels;

	void Expire()
	{
		tokens.erase(std::remove_if(tokens.begin(), tokens.end(), [](const Token &t) { return t.expires <= Anope::CurTime; }), tokens.end());
	}

	/* Built by Kyle Bargman: the forum's page for an account (by its primary nick) */
	Anope::string ProfileURL(const NickCore *nc)
	{
		Anope::string enc;
		for (char c : nc->display)
		{
			if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')
				enc.push_back(c);
			else
				enc += Anope::Format("%%%02X", static_cast<unsigned char>(c));
		}
		return forum_url + "/u/" + enc;
	}

	/* Built by Kyle Bargman: make text safe for one IRC line */
	Anope::string OneLine(const Anope::string &in, size_t max = 400)
	{
		Anope::string out;
		for (char c : in)
		{
			if (c == '\r' || c == '\n' || c == '\0')
				out.push_back(' ');
			else
				out.push_back(c);
			if (out.length() >= max)
				break;
		}
		return out;
	}

	NickCore *FindAccount(const Anope::string &name)
	{
		auto *na = NickAlias::Find(name);
		return na ? na->nc : nullptr;
	}
}

/* Built by Kyle Bargman: RPC northfire.loginToken <account> */
class LoginTokenRPC final
	: public RPC::Event
{
public:
	LoginTokenRPC(Module *o) : RPC::Event(o, "northfire.loginToken", 1) { }

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		auto *nc = FindAccount(request.data[0]);
		if (!nc)
		{
			request.Error(ERR_NO_ACCOUNT, "No such account");
			return true;
		}
		if (nc->HasExt("NS_SUSPENDED"))
		{
			request.Error(ERR_SUSPENDED, "Account suspended");
			return true;
		}

		Expire();
		/* at most a few outstanding codes per account */
		const auto lower = nc->display.lower();
		size_t mine = std::count_if(tokens.begin(), tokens.end(), [&](const Token &t) { return t.account == lower; });
		if (mine >= 5)
			tokens.erase(std::find_if(tokens.begin(), tokens.end(), [&](const Token &t) { return t.account == lower; }));

		Token t;
		t.account = lower;
		t.code = Anope::Random(43);  /* about 256 bits */
		t.expires = Anope::CurTime + TOKEN_TIME;
		tokens.push_back(t);

		Log(LOG_NORMAL, "forum") << "Forum asked for a one-time login code for " << nc->display;
		request.Root()
			.Reply("account", nc->display)
			.Reply("token", TOKEN_PREFIX + t.code)
			.Reply("expires", static_cast<int64_t>(t.expires));
		return true;
	}
};

/* Built by Kyle Bargman: RPC northfire.account <account> */
class AccountRPC final
	: public RPC::Event
{
public:
	AccountRPC(Module *o) : RPC::Event(o, "northfire.account", 1) { }

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		auto *nc = FindAccount(request.data[0]);
		if (!nc)
		{
			request.Error(ERR_NO_ACCOUNT, "No such account");
			return true;
		}
		request.Root()
			.Reply("account", nc->display)
			.Reply("suspended", nc->HasExt("NS_SUSPENDED"))
			.Reply("online", !nc->users.empty());
		return true;
	}
};

/* Built by Kyle Bargman: RPC northfire.announce <#channel> <text> */
class AnnounceRPC final
	: public RPC::Event
{
public:
	AnnounceRPC(Module *o) : RPC::Event(o, "northfire.announce", 2) { }

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		const auto &chan = request.data[0];
		bool allowed = std::any_of(announce_channels.begin(), announce_channels.end(), [&](const Anope::string &c) { return c.equals_ci(chan); });
		if (!allowed)
		{
			request.Error(ERR_NOT_ALLOWED, "Not a channel the forum may announce in");
			return true;
		}
		auto *c = Channel::Find(chan);
		auto *bi = Config->GetClient("ChanServ");
		if (!c || !bi)
		{
			request.Error(ERR_NO_CHANNEL, "The channel is empty");
			return true;
		}
		IRCD->SendPrivmsg(bi, c->name, OneLine(request.data[1]));
		request.Root().Reply("sent", true);
		return true;
	}
};

/* Built by Kyle Bargman: RPC northfire.notify <account> <text> */
class NotifyRPC final
	: public RPC::Event
{
public:
	NotifyRPC(Module *o) : RPC::Event(o, "northfire.notify", 2) { }

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		auto *nc = FindAccount(request.data[0]);
		if (!nc)
		{
			request.Error(ERR_NO_ACCOUNT, "No such account");
			return true;
		}
		const auto text = OneLine(request.data[1]);
		auto *ns = Config->GetClient("NickServ");
		if (!nc->users.empty() && ns)
		{
			for (auto *u : nc->users)
				u->SendMessage(ns, "[Forums] %s", text.c_str());
			request.Root().Reply("sent", "notice");
			return true;
		}
		if (MemoServ::service)
		{
			MemoServ::service->Send("Forums", nc->display, "[Forums] " + text, false);
			request.Root().Reply("sent", "memo");
			return true;
		}
		request.Root().Reply("sent", "none");
		return true;
	}
};

/* Built by Kyle Bargman: RPC northfire.online <#channel> */
class OnlineRPC final
	: public RPC::Event
{
public:
	OnlineRPC(Module *o) : RPC::Event(o, "northfire.online", 1) { }

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		auto *c = Channel::Find(request.data[0]);
		if (!c || c->HasMode("SECRET") || c->HasMode("PRIVATE"))
		{
			request.Error(ERR_NO_CHANNEL, "No such public channel");
			return true;
		}
		auto &root = request.Root();
		root.Reply("channel", c->name);
		auto &nicks = root.ReplyArray("nicks");
		for (const auto &[u, _] : c->users)
		{
			if (u->server && u->server->IsULined())
				continue;  /* not the services bots */
			nicks.Reply(u->nick);
		}
		return true;
	}
};

/* Built by Kyle Bargman: NickServ FORUM [nick] */
class CommandNSForum final
	: public Command
{
public:
	CommandNSForum(Module *creator) : Command(creator, "nickserv/forum", 0, 1)
	{
		this->SetDesc(_("Show the link to a forum page"));
		this->SetSyntax(_("[\037nick\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		NickCore *nc = params.empty() ? source.GetAccount() : FindAccount(params[0]);
		if (!nc)
		{
			if (params.empty())
				source.Reply(_("The forums are at %s . Sign in there with your nick and NickServ password."), forum_url.c_str());
			else
				source.Reply(_("\002%s\002 isn't a registered nick."), params[0].c_str());
			return;
		}
		source.Reply(_("Forum page for \002%s\002: %s"), nc->display.c_str(), ProfileURL(nc).c_str());
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Gives the link to a member's page on the Northfire forums "
			"(yours, or another nick's). On the forums you sign in with your nick "
			"and NickServ password, and you can chat from there in one click."));
		return true;
	}
};

class NFForum final
	: public Module
{
	LoginTokenRPC tokenrpc;
	AccountRPC accountrpc;
	AnnounceRPC announcerpc;
	NotifyRPC notifyrpc;
	OnlineRPC onlinerpc;
	CommandNSForum commandnsforum;

public:
	NFForum(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
		, tokenrpc(this)
		, accountrpc(this)
		, announcerpc(this)
		, notifyrpc(this)
		, onlinerpc(this)
		, commandnsforum(this)
	{
		this->SetAuthor("Kyle Bargman");
		this->SetVersion("1.0");
	}

	~NFForum() override
	{
		for (auto &t : tokens)
			t.code.clear();
		tokens.clear();
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &block = conf.GetModule(this);
		forum_url = block.Get<const Anope::string>("forum_url", "https://northfire.dev/forums");
		if (forum_url.length() > 1 && forum_url[forum_url.length() - 1] == '/')
			forum_url.erase(forum_url.length() - 1);
		announce_channels.clear();
		spacesepstream sep(block.Get<const Anope::string>("announce", ""));
		for (Anope::string c; sep.GetToken(c);)
			announce_channels.push_back(c);
	}

	/* Built by Kyle Bargman: a one-time login code works as the password, once */
	void OnCheckAuthentication(User *u, IdentifyRequest *req) override
	{
		const auto &pw = req->GetPassword();
		if (pw.length() <= TOKEN_PREFIX.length() || pw.compare(0, TOKEN_PREFIX.length(), TOKEN_PREFIX) != 0)
			return;

		auto *na = NickAlias::Find(req->GetAccount());
		if (!na)
			return;

		Expire();
		const auto lower = na->nc->display.lower();
		const auto code = pw.substr(TOKEN_PREFIX.length());
		for (auto it = tokens.begin(); it != tokens.end(); ++it)
		{
			if (it->account != lower || !Anope::TimingSafeEquals(it->code, code))
				continue;
			tokens.erase(it);  /* once */
			Log(LOG_NORMAL, "forum") << "One-time login code used for " << na->nc->display << " from " << req->GetAddress();
			req->SetSecondFactorDone();
			req->Success(this, na);
			return;
		}
	}
};

MODULE_INIT(NFForum)
