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
 *
 * This file contains a module that uses an external database to cache
 * dns responses.
 */

#include "config.h"
#ifdef USE_INTERNETNL
#include "internetnl/internetnl.h"
#include "util/regional.h"
#include "util/config_file.h"
#include "sldns/parseutil.h"
#include <ctype.h>
#include "util/data/dname.h"
#include "sldns/wire2str.h"
#include "util/alloc.h"
#include "util/net_help.h"
#include "services/cache/dns.h"
#include "services/localzone.h"
#include "sldns/str2wire.h"
#include "services/mesh.h"

/* Base domain, containing delegations to test zones. */ 
#define BASE_DOMAIN		"\010internet\002nl\000"
#define BASE_DOMAIN_STR		"internet.nl."
#define BASE_DOMAIN_LABS	3
/* Zone served by this Unbound instance, must be a unsigned delegation from base
 * domain. */
#define MAIL_LAB		"\011mail-test"
#define MAIL_LAB_STR		"mail-test"
#define MAIL_LAB_LABS		1
/* Zone served by this Unbound instance, must be a signed delegation from base
 * domain. */
#define SIGNED_LAB		"\016test-ns-signed"
#define SIGNED_LAB_STR		"test-ns-signed"
#define SIGNED_LAB_LABS		1
/* Zone served by this Unbound instance, must be a signed delegation from base
 * domain, with only an IPv6 glue address. */
#define SIGNED_LAB6		"\021test-ns6-signed"
#define SIGNED_LAB6_STR		"test-ns6-signed"
#define SIGNED_LAB6_LABS	1

#define CLIENT_LOG_LAB		"\004conn"
#define CLIENT_LOG_LAB_LABS	1
#define ID_LABLEN 32
#define MAIL_KEY_PREAMBLE	"interactivemailtest"
#define MX_STR 			"%s." MAIL_LAB_STR "." BASE_DOMAIN_STR \
				" MX 10 %s." SIGNED_LAB_STR "." BASE_DOMAIN_STR

static redisContext*
redis_connect(struct internetnl_env* internetnl_env)
{
	redisContext* ctx;

	ctx = redisConnectWithTimeout(internetnl_env->server_host,
		internetnl_env->server_port, internetnl_env->timeout);
	if(!ctx || ctx->err) {
		const char *errstr = "out of memory";
		if(ctx)
			errstr = ctx->errstr;
		log_err("failed to connect to redis server: %s", errstr);
		goto redis_connect_fail;
	}
	if(redisSetTimeout(ctx, internetnl_env->timeout) != REDIS_OK) {
		log_err("failed to set redis timeout");
		goto redis_connect_fail;
	}
	return ctx;

redis_connect_fail:
	if(ctx)
		redisFree(ctx);
	return NULL;
}

static int
redis_cmd(struct module_env* env, struct internetnl_env* internetnl_env,
	const char* cmd) {
	redisContext* ctx;
	redisReply* rep;

	log_assert(env->alloc->thread_num < internetnl_env->numctxs);
	ctx = internetnl_env->ctxs[env->alloc->thread_num];

	if(!ctx) {
		ctx = redis_connect(internetnl_env);
		internetnl_env->ctxs[env->alloc->thread_num] = ctx;
	}
	if(!ctx)
		return 0;

	/* Send the command and get a reply, synchronously. */
	rep = (redisReply*)redisCommand(ctx, cmd);
	if(!rep) {
		/* Once an error as a NULL-reply is returned the context cannot
		 * be reused and we'll need to set up a new connection. */
		log_err("redis_command: failed to receive a reply, "
			"closing connection: %s", ctx->errstr);
		redisFree(ctx);
		internetnl_env->ctxs[env->alloc->thread_num] = NULL;
		return 0;
	}

	/* Check error in reply to unify logging in that case.
	 * The caller may perform context-dependent checks and logging. */
	if(rep->type == REDIS_REPLY_ERROR) {
		log_err("redis: resulted in an error: %s", rep->str);
		freeReplyObject(rep);
		return 0;
	}
	if(rep->type != REDIS_REPLY_STATUS &&
		rep->type != REDIS_REPLY_INTEGER) {
		log_err("redis_store: unexpected type of reply (%d)", rep->type);
		freeReplyObject(rep);
		return 0;
	}

	freeReplyObject(rep);
	return 1;
}

static int
redis_register_mailtest(struct module_env* env,
	struct internetnl_env* internetnl_env, const char* mailtest,
	const char* testid)
{
	int n;
	/* "SET " preamble + ":" + mailtest + ":" + testid + " 1\0" */
	char cmd[4+strlen(MAIL_KEY_PREAMBLE)+1+strlen("dmarc")+1+ID_LABLEN+3]; 

	n = snprintf(cmd, sizeof(cmd), "SET %s:%s:%s 1", MAIL_KEY_PREAMBLE,
		mailtest, testid);
	if(n < 0 || n >= (int)sizeof(cmd))
		return 0;
	return redis_cmd(env, internetnl_env, cmd);
}

static int
redis_register_client(struct module_env* env,
	struct internetnl_env* internetnl_env, struct module_qstate* qstate,
	const char* clientip)
{
	int n;
	/* "SADD ns_" + qname + " " + clientip + \0" */
	char qname[LDNS_MAX_DOMAINLEN+1];
	char cmd[8+sizeof(qname)+1+128+1];

	dname_str(qstate->qinfo.qname, qname);
	n = snprintf(cmd, sizeof(cmd), "SADD ns_%s %s", qname, clientip);
	if(n < 0 || n >= (int)sizeof(cmd))
		return 0;
	return redis_cmd(env, internetnl_env, cmd);
}

int 
internetnl_init(struct module_env* env, int id)
{
	int i;
	struct internetnl_env* internetnl_env = (struct internetnl_env*)calloc(1,
		sizeof(struct internetnl_env));
	if(!internetnl_env) {
		log_err("malloc failure");
		return 0;
	}
	env->modinfo[id] = (void*)internetnl_env;

	internetnl_env->numctxs = env->cfg->num_threads;
	internetnl_env->ctxs = calloc(env->cfg->num_threads, sizeof(redisContext*));
	if(!internetnl_env->ctxs) {
		log_err("out of memory");
		free(internetnl_env);
		return 0;
	}
	/* note: server_host is a shallow reference to configured string.
	 * we don't have to free it in this module. */
	internetnl_env->server_host = env->cfg->redis_server_host;
	internetnl_env->server_port = env->cfg->redis_server_port;
	internetnl_env->timeout.tv_sec = env->cfg->redis_timeout / 1000;
	internetnl_env->timeout.tv_usec = (env->cfg->redis_timeout % 1000) * 1000;
	for(i = 0; i < internetnl_env->numctxs; i++)
		internetnl_env->ctxs[i] = redis_connect(internetnl_env);
	return 1;
}

void 
internetnl_deinit(struct module_env* env, int id)
{
	struct internetnl_env* internetnl_env;
	if(!env || !env->modinfo[id])
		return;
	internetnl_env = (struct internetnl_env*)env->modinfo[id];

	if(internetnl_env->ctxs) {
		int i;
		for(i = 0; i < internetnl_env->numctxs; i++) {
			if(internetnl_env->ctxs[i])
				redisFree(internetnl_env->ctxs[i]);
		}
		free(internetnl_env->ctxs);
	}

	free(internetnl_env);
	env->modinfo[id] = NULL;
}

/** new query for internetnl */
static int
internetnl_new(struct module_qstate* qstate, int id)
{
	struct internetnl_qstate* iq = (struct internetnl_qstate*)regional_alloc(
		qstate->region, sizeof(struct internetnl_qstate));
	qstate->minfo[id] = iq;
	if(!iq) 
		return 0;
	memset(iq, 0, sizeof(*iq));
	/* initialise it */
	/* TODO */

	return 1;
}

/**
 * Return an error
 * @param qstate: our query state
 * @param id: module id
 * @param rcode: error code (DNS errcode).
 * @return: 0 for use by caller, to make notation easy, like:
 * 	return error_response(..). 
 */
static int
error_response(struct module_qstate* qstate, int id, int rcode)
{
	verbose(VERB_QUERY, "return error response %s", 
		sldns_lookup_by_id(sldns_rcodes, rcode)?
		sldns_lookup_by_id(sldns_rcodes, rcode)->name:"??");
	qstate->return_rcode = rcode;
	qstate->return_msg = NULL;
	qstate->ext_state[id] = module_finished;
	return 0;
}

/**
 * Compare a specific label in the domain name with given label
 * @param dname: dname containing compairing label
 * @param labnum: label to test, first label is 1
 * @param lab: label to compair against
 * @return: 1 is label matches, 0 otherwise.
 */
static int
lab_cmp(uint8_t* dname, int labnum, uint8_t* lab)
{
        int lablen;
        /* go to desired label */
        while(--labnum) {
		if(dname[0]== 0)
			return 0;
                dname += dname[0] + 1;
        }

        lablen = dname[0];
        while(lablen--) {
                if(tolower((unsigned char)*dname) != tolower((unsigned char)*lab))
                        return 0;
                dname++; lab++;
        }

        return 1;
}

/**
 * Write Nth label of dname as string into buffer
 * @param dname: dname to get label from
 * @param labnum: number of label to get pointer to
 * @param buf: buffer to write label string into
 * @param buflen: length of buffer
 * @return: 1 if written succesful, 0 otherwise
 */
static int
dname_lab_str(uint8_t* dname, int labnum, char* buf, size_t buflen)
{
	uint8_t lablen;
        /* go to desired label */
        while(--labnum) {
		if(dname[0] == 0)
			return 0;
                dname += dname[0] + 1;
        }
	if(dname[0] >= buflen)
		/* label does not fit is buffer, return NULL */
		return 0;
	lablen = dname[0];
	dname++;
	while(lablen--) {
		if(!isalnum((unsigned char)*dname) && *dname != '-' &&
			*dname != '_' )
			return 0;
		*buf++ = (unsigned char)*dname++;
	}
	*buf = '\0';
	return 1;
}

static void
internetnl_handle_query(struct module_qstate* qstate,
	struct internetnl_qstate* ATTR_UNUSED(iq), struct internetnl_env* ie,
	int id)
{
	char testid[ID_LABLEN+1];
	testid[ID_LABLEN] = '\0';

	verbose(VERB_QUERY, "internetnll %d", qstate->qinfo.qtype);
	if(dname_strict_subdomain(
		qstate->qinfo.qname, dname_count_labels(qstate->qinfo.qname),
		(uint8_t*)MAIL_LAB BASE_DOMAIN, MAIL_LAB_LABS + BASE_DOMAIN_LABS)) {
		if(qstate->qinfo.qtype == LDNS_RR_TYPE_TXT &&
			dname_count_labels(qstate->qinfo.qname) == 
			MAIL_LAB_LABS + BASE_DOMAIN_LABS + 1) {
			/* SPF query, 1st label is ID */	
			if(!dname_lab_str(qstate->qinfo.qname, 1, testid, ID_LABLEN+1))
				goto bail_out;
			if(!redis_register_mailtest(qstate->env, ie, "spf",
				(char*)testid))
				goto bail_out;
		}
		else if(qstate->qinfo.qtype == LDNS_RR_TYPE_TXT && 
			lab_cmp(qstate->qinfo.qname, 1, (uint8_t*)"\006_dmarc") &&
			dname_count_labels(qstate->qinfo.qname) == 
			MAIL_LAB_LABS + BASE_DOMAIN_LABS + 2) {
			/* DMARC record, 2nd label is ID */	
			if(!dname_lab_str(qstate->qinfo.qname, 2, testid, ID_LABLEN+1))
				goto bail_out;
			if(!redis_register_mailtest(qstate->env, ie, "dmarc",
				(char*)testid))
				goto bail_out;
		}
		else if(qstate->qinfo.qtype == LDNS_RR_TYPE_TXT && 
			lab_cmp(qstate->qinfo.qname, 1, (uint8_t*)"\010selector") &&
			lab_cmp(qstate->qinfo.qname, 2, (uint8_t*)"\012_domainkey") &&
			dname_count_labels(qstate->qinfo.qname) ==
			MAIL_LAB_LABS + BASE_DOMAIN_LABS + 3) {
			/* DKIM, 3nd label is ID */	
			if(!dname_lab_str(qstate->qinfo.qname, 3, testid, ID_LABLEN+1))
				goto bail_out;
			if(!redis_register_mailtest(qstate->env, ie, "dkim",
				(char*)testid))
				goto bail_out;
		}
		else if(qstate->qinfo.qtype == LDNS_RR_TYPE_MX &&
			dname_count_labels(qstate->qinfo.qname) == 
			MAIL_LAB_LABS + BASE_DOMAIN_LABS + 1) {
			/* Do not let the iterator cache this result */
			qstate->no_cache_store = 1;
		}
	}
	else if(dname_strict_subdomain(
		qstate->qinfo.qname, dname_count_labels(qstate->qinfo.qname),
		(uint8_t*)SIGNED_LAB BASE_DOMAIN,
		SIGNED_LAB_LABS + BASE_DOMAIN_LABS) &&
		/*qstate->qinfo.qtype == LDNS_RR_TYPE_TLSA &&*/
		lab_cmp(qstate->qinfo.qname, 1, (uint8_t*)"\003_25") &&
		lab_cmp(qstate->qinfo.qname, 2, (uint8_t*)"\004_tcp") &&
		dname_count_labels(qstate->qinfo.qname) == 
		SIGNED_LAB_LABS + BASE_DOMAIN_LABS + 3) {
		/* DANE for SMTP, 3nd label is ID */	
		if(!dname_lab_str(qstate->qinfo.qname, 3, testid, ID_LABLEN+1))
			goto bail_out;
		if(!redis_register_mailtest(qstate->env, ie, "dane",
			(char*)testid))
			goto bail_out;
	}
	else if(dname_strict_subdomain(qstate->qinfo.qname,
		dname_count_labels(qstate->qinfo.qname),
		(uint8_t*)CLIENT_LOG_LAB SIGNED_LAB BASE_DOMAIN,
		CLIENT_LOG_LAB_LABS + SIGNED_LAB_LABS + BASE_DOMAIN_LABS) ||
		dname_strict_subdomain(qstate->qinfo.qname,
		dname_count_labels(qstate->qinfo.qname),
		(uint8_t*)CLIENT_LOG_LAB SIGNED_LAB6 BASE_DOMAIN,
		CLIENT_LOG_LAB_LABS + SIGNED_LAB_LABS + BASE_DOMAIN_LABS)) {
		/* Register for connection test, where key = ns_<qname> and
		 * value is list of source addresses */
		char clientip_buf[128];
		if(qstate->mesh_info->reply_list) {
			addr_to_str(
			&qstate->mesh_info->reply_list->query_reply.addr,
			qstate->mesh_info->reply_list->query_reply.addrlen,
			clientip_buf, sizeof(clientip_buf));
		}
		if(!redis_register_client(qstate->env, ie, qstate,
			clientip_buf))
			goto bail_out;
	}
	qstate->ext_state[id] = module_wait_module;
	return;
bail_out:
	qstate->ext_state[id] = module_finished;
}

/** allocate and initialize an rrset structure; this function is based
 * on new_local_rrset() from the localzone.c module */
static struct ub_packed_rrset_key*
rrset_from_str(struct regional* region, const char* rrstr)
{
	uint16_t rrtype = 0, rrclass = 0;
	time_t ttl = 0;
	uint8_t rr[LDNS_RR_BUF_SIZE];
	uint8_t* rdata = NULL;
	int e;
	size_t dname_len = 0, rdata_len = 0, rr_len = 0;
	struct packed_rrset_data* pd;
	struct ub_packed_rrset_key* rrset = regional_alloc_zero(
		region, sizeof(*rrset));
	if(!rrset) {
		log_err("out of memory");
		return NULL;
	}

	rrset->entry.key = rrset;
	pd = regional_alloc_zero(region, sizeof(*pd));
	if(!pd) {
		log_err("out of memory");
		return NULL;
	}
	pd->trust = rrset_trust_prim_noglue;
	pd->security = sec_status_insecure;
	rrset->entry.data = pd;
	rr_len = sizeof(rr);
	e = sldns_str2wire_rr_buf(rrstr, rr, &rr_len, &dname_len, 3600,
		NULL, 0, NULL, 0);
	if(e) {
		log_err("error parsing rrset at %d: '%s': %s",
			LDNS_WIREPARSE_OFFSET(e), rrstr,
			sldns_get_errorstr_parse(e));
		return NULL;
	}
	rrset->rk.dname = regional_alloc_init(region, rr, dname_len);
	if(!rrset->rk.dname) {
		log_err("out of memory");
		return NULL;
	}
	rrset->rk.dname_len = dname_len;
	rrset->rk.rrset_class = htons(sldns_wirerr_get_class(rr, rr_len, dname_len));
	rrset->rk.type = htons(sldns_wirerr_get_type(rr, rr_len, dname_len));
	ttl = (time_t)sldns_wirerr_get_ttl(rr, rr_len, dname_len);
	rdata = sldns_wirerr_get_rdatawl(rr, rr_len, dname_len);
	rdata_len = sldns_wirerr_get_rdatalen(rr, rr_len, dname_len)+2;
	rrset_insert_rr(region, pd, rdata, rdata_len, ttl, rrstr);
	return rrset;
}

static void
internetnl_handle_response(struct module_qstate* qstate,
	struct internetnl_qstate* ATTR_UNUSED(iq), struct internetnl_env* ie,
	int id)
{
	char testid[ID_LABLEN+1];
	struct rrset_parse* rrset, *prev;
	testid[ID_LABLEN] = '\0';

	/* Make answer authoritative */
	if(qstate->return_msg)
		qstate->return_msg->rep->flags |= BIT_AA;
	qstate->ext_state[id] = module_finished;

	if(dname_strict_subdomain(
		qstate->qinfo.qname, dname_count_labels(qstate->qinfo.qname),
		(uint8_t*)MAIL_LAB BASE_DOMAIN, 4) &&
		qstate->qinfo.qtype == LDNS_RR_TYPE_MX &&
		dname_count_labels(qstate->qinfo.qname) == 5) {
			/* Inject unique mx host */
			struct reply_info* new_rep = NULL;
			struct ub_packed_rrset_key* mxrr = NULL;
			char mxstr[sizeof(testid)*2+sizeof(MX_STR)];

			/* MX query, 1st label is ID */	
			if(!dname_lab_str(qstate->qinfo.qname, 1, testid,
				ID_LABLEN+1))
				return;
			snprintf(mxstr, sizeof(mxstr), MX_STR, testid, testid);
			if(!(mxrr = rrset_from_str(qstate->region, mxstr)))
				return;
			new_rep = construct_reply_info_base(
				qstate->region, qstate->return_msg->rep->flags,
				qstate->return_msg->rep->qdcount, 
				qstate->return_msg->rep->ttl, 
				qstate->return_msg->rep->prefetch_ttl,
				qstate->return_msg->rep->serve_expired_ttl,
				1, 0, 0, 1,
				sec_status_insecure);
			if(!new_rep)
				return;
			if(!reply_info_alloc_rrset_keys(new_rep, NULL,
				qstate->region))
				return;
			new_rep->rrsets[0] = mxrr;
			qstate->return_msg->rep = new_rep;
			qstate->return_msg->rep->flags |= BIT_AA;
	}
}

void 
internetnl_operate(struct module_qstate* qstate, enum module_ev event, int id,
	struct outbound_entry* outbound)
{
	struct internetnl_env* ie = (struct internetnl_env*)qstate->env->modinfo[id];
	struct internetnl_qstate* iq = (struct internetnl_qstate*)qstate->minfo[id];
	verbose(VERB_QUERY, "internetnl[module %d] operate: extstate:%s event:%s", 
		id, strextstate(qstate->ext_state[id]), strmodulevent(event));
	if(iq) log_query_info(VERB_QUERY, "internetnl operate: query", 
		&qstate->qinfo);

	/* perform internetnl state machine */
	if((event == module_event_new || event == module_event_pass) && 
		iq == NULL) {
		if(!internetnl_new(qstate, id)) {
			(void)error_response(qstate, id, LDNS_RCODE_SERVFAIL);
			return;
		}
		iq = (struct internetnl_qstate*)qstate->minfo[id];
	}
	if(iq && (event == module_event_pass || event == module_event_new)) {
		internetnl_handle_query(qstate, iq, ie, id);
		return;
	}
	if(iq && (event == module_event_moddone)) {
		internetnl_handle_response(qstate, iq, ie, id);
		return;
	}
	if(iq && outbound) {
		return;
	}
	if(event == module_event_error) {
		verbose(VERB_ALGO, "got called with event error, giving up");
		(void)error_response(qstate, id, LDNS_RCODE_SERVFAIL);
		return;
	}
	if(!iq && (event == module_event_moddone)) {
		/* during priming, module done but we never started */
		qstate->ext_state[id] = module_finished;
		return;
	}

	log_err("bad event for internetnl");
	(void)error_response(qstate, id, LDNS_RCODE_SERVFAIL);
}

void
internetnl_inform_super(struct module_qstate* ATTR_UNUSED(qstate),
	int ATTR_UNUSED(id), struct module_qstate* ATTR_UNUSED(super))
{
	/* internetnl does not use subordinate requests at this time */
	verbose(VERB_ALGO, "internetnl inform_super was called");
}

void 
internetnl_clear(struct module_qstate* qstate, int id)
{
	if(!qstate)
		return;
	qstate->minfo[id] = NULL;
}

size_t 
internetnl_get_mem(struct module_env* env, int id)
{
	struct internetnl_env* ie = (struct internetnl_env*)env->modinfo[id];
	if(!ie)
		return 0;
	return sizeof(*ie); /* TODO - more mem */
}

/**
 * The internetnl function block 
 */
static struct module_func_block internetnl_block = {
	"internetnl",
	&internetnl_init, &internetnl_deinit, &internetnl_operate,
	&internetnl_inform_super, &internetnl_clear, &internetnl_get_mem
};

struct module_func_block* 
internetnl_get_funcblock(void)
{
	return &internetnl_block;
}
#endif /* USE_INTERNETNL */
