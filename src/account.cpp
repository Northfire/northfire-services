// Anope IRC Services <https://www.anope.org/>
//
// Copyright (C) 2003-2026 Anope Contributors
//
// Anope is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// Based on the original code of Epona by Lara
// Based on the original code of Services by Andy Church
//
// SPDX-License-Identifier: GPL-2.0-only

#include "services.h"
#include "account.h"
#include "modules.h"
#include "users.h"
#include "protocol.h"
#include "regchannel.h"

std::set<IdentifyRequest *> IdentifyRequest::Requests;

IdentifyRequest::IdentifyRequest(Module *o, const Anope::string &acc, const Anope::string &pass, const Anope::string &ip)
	: owner(o)
	, account(acc)
	, password(pass)
	, address(ip)
{
	Requests.insert(this);
}

IdentifyRequest::~IdentifyRequest()
{
	Requests.erase(this);
}

void IdentifyRequest::Hold(Module *m)
{
	holds.insert(m);
}

void IdentifyRequest::Release(Module *m)
{
	holds.erase(m);
	if (holds.empty() && dispatched)
		this->Finish();
}

void IdentifyRequest::Success(Module *m, NickAlias *na)
{
	if (success || blocked)
		return;
	password_right = true;
	if (this->Gate())
		return;

	/* Northfire: a right password can still need a second step (nf_twostep). Built by Kyle Bargman */
	EventReturn MOD_RESULT;
	FOREACH_RESULT(OnIdentifySecondFactor, MOD_RESULT, (this, na));
	if (MOD_RESULT == EVENT_STOP)
	{
		blocked = true;
		if (refusal.empty())
			refusal = "second-factor";
		return;
	}

	this->OnSuccess(na);
	success = true;
}

/* Northfire: one place where a module may refuse a sign-in, whatever the
 * route (IDENTIFY, SASL, RECOVER, GROUP, webcpanel, RPC). Built by Kyle Bargman */
bool IdentifyRequest::Gate()
{
	if (!gated)
	{
		gated = true;
		EventReturn MOD_RESULT;
		FOREACH_RESULT(OnIdentifyGate, MOD_RESULT, (this));
		blocked = MOD_RESULT == EVENT_STOP;
		if (blocked && refusal.empty())
			refusal = "locked";
	}
	return blocked;
}

/* Northfire: finish the request and report the outcome. Built by Kyle Bargman */
void IdentifyRequest::Finish()
{
	if (!success)
	{
		this->Gate();
		this->OnFail();
	}
	FOREACH_MOD(OnIdentifyResult, (this));
	delete this;
}

void IdentifyRequest::Dispatch()
{
	if (holds.empty())
		this->Finish();
	else
		dispatched = true;
}

void IdentifyRequest::ModuleUnload(Module *m)
{
	for (auto it = Requests.begin(), it_end = Requests.end(); it != it_end;)
	{
		IdentifyRequest *ir = *it;
		++it;

		ir->holds.erase(m);
		if (ir->holds.empty() && ir->dispatched)
		{
			ir->Finish();
			continue;
		}

		if (ir->owner == m)
		{
			/* The module that made the request is going away: no result event,
			 * as the request's own code is being unloaded. */
			if (!ir->success)
				ir->OnFail();
			delete ir;
		}
	}
}
