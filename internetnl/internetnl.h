/*
 * internetnl/internetnl.c - Unbound module for internet.nl tests
 *
 * Copyright (c) 2018, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 * TODO
 */
#include "util/module.h"
#include "hiredis/hiredis.h"

/**
 */
struct internetnl_env {
	redisContext** ctxs;	/* thread-specific redis contexts */
	int numctxs;		/* number of ctx entries */
	const char* server_host; /* server's IP address or host name */
	int server_port;	 /* server's TCP port */
	struct timeval timeout;	 /* timeout for connection setup and commands */
};

/**
 * Per query state for the internetnl module.
 */
struct internetnl_qstate {
	int todo;
};

/** Init the internetnl module */
int internetnl_init(struct module_env* env, int id);
/** Deinit the internetnl module */
void internetnl_deinit(struct module_env* env, int id);
/** Operate on an event on a query (in qstate). */
void internetnl_operate(struct module_qstate* qstate, enum module_ev event,
	int id, struct outbound_entry* outbound);
/** Subordinate query done, inform this super request of its conclusion */
void internetnl_inform_super(struct module_qstate* qstate, int id,
	struct module_qstate* super);
/** clear the internetnl query-specific contents out of qstate */
void internetnl_clear(struct module_qstate* qstate, int id);
/** return memory estimate for internetnl module */
size_t internetnl_get_mem(struct module_env* env, int id);

/**
 * Get the function block with pointers to the internetnl functions
 * @return the function block for "internetnl".
 */
struct module_func_block* internetnl_get_funcblock(void);

