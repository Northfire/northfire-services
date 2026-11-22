/*
 * Northfire Services: tell an account's owner about something that happened to it.
 *
 * Built by Kyle Bargman, 2026-11-22, for the Northfire IRC Network.
 *
 * Used by nf_security, nf_authguard and nf_twostep. A security notice goes:
 *  - as a NickServ notice to every connection signed in to the account,
 *  - as a memo (so it is there the next time they sign in, whatever their client), and
 *  - by email to the account's address, and to extra_email too (the old address,
 *    after an email change), when services mail is set up.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include "module.h"
#include "modules/memoserv/service.h"

namespace NFNotify
{
	/* Built by Kyle Bargman: the address a sign-in is counted under (IPv6 by /64); shared with nf_authguard */
	inline Anope::string AddressKey(const Anope::string &ip)
	{
		if (ip.empty())
			return "unknown";
		if (ip.find(':') == Anope::string::npos)
			return ip;

		sockaddrs a;
		try
		{
			a.pton(AF_INET6, ip);
		}
		catch (const SocketException &)
		{
			return ip;
		}
		if (!a.valid())
			return ip;
		memset(&a.sa6.sin6_addr.s6_addr[8], 0, 8);
		return a.addr() + "/64";
	}

	/* Built by Kyle Bargman: the notice, memo and email for one security event.
	 * text is one or two plain sentences; it is used for all three. */
	inline void Owner(NickCore *nc, const Anope::string &subject, const Anope::string &text, const Anope::string &extra_email = "")
	{
		if (!nc)
			return;

		auto *ns = Config->GetClient("NickServ");
		if (ns)
		{
			for (auto *u : nc->users)
				u->SendMessage(ns, "\002Security notice:\002 " + text);
		}

		if (MemoServ::service && ns)
			MemoServ::service->Send(ns->nick, nc->display, "Security notice: " + text, true);

		const Anope::string body = "Hello " + nc->display + ",\n\n" + text + "\n\n"
			"If this was you, there is nothing to do. If it wasn't, sign in on IRC, change your "
			"password with /msg NickServ SET PASSWORD, and ask a network operator for help.\n\n"
			"Northfire IRC Network\n";
		Mail::Send(nc, "Northfire: " + subject, body);
		if (!extra_email.empty() && !extra_email.equals_ci(nc->email))
			Mail::SendTo(nc->display, extra_email, "Northfire: " + subject, body);
	}

	/* Built by Kyle Bargman: how the change was made, for the notice ("" if by the owner) */
	inline Anope::string ByWhom(CommandSource &source, NickCore *nc)
	{
		if (source.GetAccount() == nc)
			return "";
		if (source.GetAccount())
			return " by services staff (" + source.GetAccount()->display + ")";
		return " by services staff";
	}
}
