/*
 * Northfire Services: nf_tlsonly - passwords only over TLS.
 *
 * Built by Kyle Bargman, 2026-11-22, for the Northfire IRC Network.
 *
 * Refuses NickServ commands that carry a password (IDENTIFY, REGISTER,
 * RECOVER, GROUP, SET PASSWORD) from people who aren't connected securely,
 * and tells them how to reconnect. SASL is not affected: the IRC server
 * decides whether to allow SASL on plain connections.
 *
 * module
 * {
 *     name = "nf_tlsonly"
 *     commands = "nickserv/identify nickserv/register nickserv/recover nickserv/group nickserv/set/password nickserv/twostep"
 *     message = "Connect with TLS (port 6697) to use passwords; your password was not checked."
 * }
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "module.h"

class NFTLSOnly final
	: public Module
{
	std::set<Anope::string, ci::less> commands;
	Anope::string message;

public:
	NFTLSOnly(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
	{
		this->SetAuthor("Kyle Bargman");
		this->SetVersion("1.0");
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &block = conf.GetModule(this);
		commands.clear();
		spacesepstream sep(block.Get<const Anope::string>("commands",
			"nickserv/identify nickserv/register nickserv/recover nickserv/group nickserv/set/password nickserv/twostep"));
		for (Anope::string c; sep.GetToken(c);)
			commands.insert(c);
		message = block.Get<const Anope::string>("message",
			"For your safety, passwords are only accepted over a secure connection. "
			"Reconnect using TLS (port 6697) and try again; your password was not checked or saved.");
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) override
	{
		auto *u = source.GetUser();
		if (!u || u->IsSecurelyConnected() || !commands.count(command->name))
			return EVENT_CONTINUE;

		/* RECOVER and GROUP without a password use the access list / certificate */
		if ((command->name == "nickserv/recover" || command->name == "nickserv/group") && params.size() < 2)
			return EVENT_CONTINUE;

		Log(this, "refused") << u->GetMask() << " used " << command->name << " without TLS";
		source.Reply("%s", message.c_str());
		return EVENT_STOP;
	}
};

MODULE_INIT(NFTLSOnly)
