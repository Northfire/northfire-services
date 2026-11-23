/*
 * Northfire Services: nf_passpolicy - no weak passwords.
 *
 * Built by Kyle Bargman, 2026-11-22, for the Northfire IRC Network.
 *
 * REGISTER, SET PASSWORD and SASET PASSWORD refuse a password that is
 *   - shorter than min_length (default 8),
 *   - the nick or account in it (or it in them), or
 *   - one of the 100,000 passwords most seen in breaches (common-passwords.txt in
 *     the config directory: the NCSC list, kept here, so nothing is looked up elsewhere).
 * RPC northfire.checkPassword <password> [nick] gives the same verdict to the forum.
 *
 *   module { name = "nf_passpolicy"; min_length = 8; list = "common-passwords.txt"; }
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "module.h"
#include "modules/rpc.h"
#include <fstream>
#include <unordered_set>

namespace
{
	std::unordered_set<std::string> common;
	unsigned min_length = 8;

	/* Built by Kyle Bargman: why a password is too weak, or "" if it's fine */
	Anope::string Weakness(const Anope::string &pass, const std::vector<Anope::string> &names)
	{
		if (pass.length() < min_length)
			return Anope::Format(_("is too short: use at least %u characters (a few words together is easy to remember)"), min_length);

		const auto lower = pass.lower();
		for (const auto &name : names)
		{
			const auto n = name.lower();
			if (n.length() >= 4 && (lower.find(n) != Anope::string::npos || (lower.length() >= 4 && n.find(lower) != Anope::string::npos)))
				return _("has your nick in it, which is the first thing anyone would try");
		}

		/* one character over and over (aaaaaaaa, 11111111) */
		if (std::all_of(lower.begin(), lower.end(), [&](char c) { return c == lower[0]; }))
			return _("is one character over and over");

		if (common.count(lower.str()))
			return _("is one of the most common passwords, the ones guessed first");

		return "";
	}
}

/* Built by Kyle Bargman: RPC northfire.checkPassword <password> [nick] */
class CheckPasswordRPC final
	: public RPC::Event
{
public:
	CheckPasswordRPC(Module *o) : RPC::Event(o, "northfire.checkPassword", 1) { }

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		std::vector<Anope::string> names;
		if (request.data.size() > 1)
		{
			names.push_back(request.data[1]);
			if (auto *na = NickAlias::Find(request.data[1]))
				names.push_back(na->nc->display);
		}
		const auto why = Weakness(request.data[0], names);
		request.Root().Reply("ok", why.empty()).Reply("why", why);
		return true;
	}
};

class NFPassPolicy final
	: public Module
{
	CheckPasswordRPC checkrpc;

	static void LoadList(const Anope::string &file)
	{
		common.clear();
		std::ifstream in(Anope::ExpandConfig(file).str());
		if (!in.is_open())
		{
			Log() << "nf_passpolicy: can't read " << file << ", so only the length and nick rules apply";
			return;
		}
		for (std::string line; std::getline(in, line);)
		{
			if (!line.empty() && line.back() == '\r')
				line.pop_back();
			if (line.empty() || line[0] == '#')
				continue;
			common.insert(Anope::string(line).lower().str());
		}
		Log() << "nf_passpolicy: " << common.size() << " common passwords loaded";
	}

public:
	NFPassPolicy(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
		, checkrpc(this)
	{
		this->SetAuthor("Kyle Bargman");
		this->SetVersion("1.0");
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &block = conf.GetModule(this);
		min_length = std::max(6u, block.Get<unsigned>("min_length", "8"));
		LoadList(block.Get<const Anope::string>("list", "common-passwords.txt"));
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) override
	{
		Anope::string pass;
		std::vector<Anope::string> names;
		if (command->name == "nickserv/register" && !params.empty())
		{
			pass = params[0];
			names.push_back(source.GetNick());
		}
		else if (command->name == "nickserv/set/password" && !params.empty())
		{
			pass = params[0];
			names.push_back(source.GetNick());
			if (source.GetAccount())
				names.push_back(source.GetAccount()->display);
		}
		else if (command->name == "nickserv/saset/password" && params.size() >= 2)
		{
			pass = params[1];
			names.push_back(params[0]);
			if (auto *na = NickAlias::Find(params[0]))
				names.push_back(na->nc->display);
		}
		else
			return EVENT_CONTINUE;

		const auto why = Weakness(pass, names);
		if (why.empty())
			return EVENT_CONTINUE;

		source.Reply(_("That password %s. Please choose another."), why.c_str());
		return EVENT_STOP;
	}
};

MODULE_INIT(NFPassPolicy)
