/*
 * Zebra SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2020  Masakazu Asama
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "srv6.h"
#include "zebra/debug.h"
#include "zebra/zapi_msg.h"
#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_errors.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>


DEFINE_MGROUP(SRV6_MGR, "SRv6 Manager");
DEFINE_MTYPE_STATIC(SRV6_MGR, SRV6M_CHUNK, "SRv6 Manager Chunk");

/* define hooks for the basic API, so that it can be specialized or served
 * externally
 */

DEFINE_HOOK(srv6_manager_client_connect,
	    (struct zserv *client, vrf_id_t vrf_id),
	    (client, vrf_id));
DEFINE_HOOK(srv6_manager_client_disconnect,
	    (struct zserv *client), (client));
DEFINE_HOOK(srv6_manager_get_chunk,
	    (struct srv6_locator **loc,
	     struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (loc, client, locator_name, vrf_id));
DEFINE_HOOK(srv6_manager_release_chunk,
	    (struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (client, locator_name, vrf_id));

/* define wrappers to be called in zapi_msg.c (as hooks must be called in
 * source file where they were defined)
 */

void srv6_manager_client_connect_call(struct zserv *client, vrf_id_t vrf_id)
{
	hook_call(srv6_manager_client_connect, client, vrf_id);
}

void srv6_manager_get_locator_chunk_call(struct srv6_locator **loc,
					 struct zserv *client,
					 const char *locator_name,
					 vrf_id_t vrf_id)
{
	hook_call(srv6_manager_get_chunk, loc, client, locator_name, vrf_id);
}

void srv6_manager_release_locator_chunk_call(struct zserv *client,
					     const char *locator_name,
					     vrf_id_t vrf_id)
{
	hook_call(srv6_manager_release_chunk, client, locator_name, vrf_id);
}

int srv6_manager_client_disconnect_cb(struct zserv *client)
{
	hook_call(srv6_manager_client_disconnect, client);
	return 0;
}


static void set_seg6local_end(struct prefix_ipv6 *prefix)
{
	struct route_entry *re;
	struct nexthop_group *ng;
	struct vrf *vrf;
	struct interface *ifp;
	struct nexthop *nexthop;
	int ret;
	ifindex_t ifindex;

	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = ZEBRA_ROUTE_STATIC;
	re->instance = 0;
	re->uptime = monotime(NULL);
	re->vrf_id = VRF_DEFAULT;
	re->table = RT_TABLE_MAIN;
	SET_FLAG(re->flags, ZEBRA_FLAG_SEG6LOCAL_ROUTE);

	ifindex = 1;
	vrf = vrf_lookup_by_id(VRF_DEFAULT);
	FOR_ALL_INTERFACES (vrf, ifp) {
		if (ifp->ifindex == 1)
			continue;
		if (!if_is_operative(ifp))
			continue;
		ifindex = ifp->ifindex;
		break;
	}

	if (ifindex == 1)
		zlog_err("%s: no available interface on default-vrf",
			 __func__);

	ng = nexthop_group_new();
	nexthop = nexthop_from_ifindex(ifindex, VRF_DEFAULT);
	if (!nexthop) {
		flog_warn(
			EC_ZEBRA_NEXTHOP_CREATION_FAILED,
			"%s: Nexthops Specified: but we failed to properly create one",
			__PRETTY_FUNCTION__);
		nexthop_group_delete(&ng);
		XFREE(MTYPE_RE, re);
		return;
	}

	nexthop_add_seg6local(nexthop, ZEBRA_SEG6_LOCAL_ACTION_END, NULL);
	nexthop_group_add_sorted(ng, nexthop);

	ret = rib_add_multipath(AFI_IP6, SAFI_UNICAST,
				(struct prefix *)prefix, NULL, re, ng);
	if (ret < 0)
		zlog_err("%s: can't add RE entry to rib", __func__);
}

static void locator_init(const struct srv6_locator *loc)
{
	size_t idx_hi, idx_lo;
	uint16_t value = 0x0001;
	struct prefix_ipv6 p;
	struct srv6_function *function;

	idx_hi = loc->prefix.prefixlen / 8;
	idx_lo = idx_hi + 1;

	p = loc->prefix;
	p.prefix.s6_addr[idx_hi] = (0xff00 & value) >> 8;
	p.prefix.s6_addr[idx_lo] = (0x00ff & value);
	p.prefixlen = loc->prefix.prefixlen + loc->function_bits_length;
	set_seg6local_end(&p);

	function = srv6_function_alloc(&p);
	listnode_add(loc->functions, function);
	strlcpy(function->locator_name, loc->name,
		sizeof(function->locator_name));
}

static void get_function_addr(struct in6_addr *locator,
			      uint64_t current, int lshift)
{
	uint32_t *p = (uint32_t *)locator;
	uint32_t tmp[4] = {};

	if (lshift > 0x5f)
		return;

	tmp[lshift >> 5] = current << (lshift & 0x1f);
	tmp[(lshift >> 5) + 1] = current >> (32 - (lshift & 0x1f));
	p[0] |= ntohl(tmp[3]);
	p[1] |= ntohl(tmp[2]);
	p[2] |= ntohl(tmp[1]);
	p[3] |= ntohl(tmp[0]);
}

static int zebra_srv6_cleanup(struct zserv *client)
{
	return 0;
}

void zebra_srv6_locator_add(struct srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *tmp;

	tmp = zebra_srv6_locator_lookup(locator->name);
	if (!tmp)
		listnode_add(srv6->locators, locator);
	zsend_bcast_zebra_srv6_locator_add(locator);
	locator_init(locator);
}

void zebra_srv6_locator_delete(struct srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node;
	struct srv6_function *function;

	for (ALL_LIST_ELEMENTS_RO((struct list *)locator->functions,
				  node, function))
		zsend_bcast_zebra_srv6_function_delete(function);
	zsend_bcast_zebra_srv6_locator_delete(locator);
	listnode_delete(srv6->locators, locator);
}

struct srv6_locator *zebra_srv6_locator_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		if (!strncmp(name, locator->name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

void zebra_srv6_function_add(struct srv6_function *function,
			     struct srv6_locator *locator)
{
	listnode_add(locator->functions, function);
	strlcpy(function->locator_name, locator->name,
		sizeof(function->locator_name));
	zsend_bcast_zebra_srv6_function_add(function);
}

void zebra_srv6_function_delete(struct srv6_function *function,
				struct srv6_locator *locator)
{
	zsend_bcast_zebra_srv6_function_delete(function);
	listnode_delete(locator->functions, function);
}

struct srv6_function *zebra_srv6_function_lookup(
		const struct srv6_locator *locator,
		const struct prefix_ipv6 *prefix)
{
	struct srv6_function *function;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(locator->functions, node, function))
		if (!prefix_cmp(prefix, &function->prefix))
			return function;
	return NULL;
}

void zrecv_zebra_srv6_function_add(ZAPI_HANDLER_ARGS)
{
	struct srv6_function api;
	struct srv6_locator *locator;
	struct srv6_function *function;
	struct prefix_ipv6 addr_zero = {.family = AF_INET6};
	int function_prefixlen;

	zapi_srv6_function_decode(msg, &api);
	locator = zebra_srv6_locator_lookup(api.locator_name);
	if (!locator) {
		zlog_err("%s: locator '%s' is not found", __func__,
			 api.locator_name);
		return;
	}
	function_prefixlen = locator->prefix.prefixlen
		+ locator->function_bits_length;
	if (api.prefix.prefixlen != 0 &&
	    api.prefix.prefixlen != function_prefixlen) {
		zlog_err("%s: function prefixlen mis-match", __func__);
		return;
	}
	if (!prefix_same(&api.prefix, &addr_zero)
	 && !prefix_match((const struct prefix *)&locator->prefix,
			  (const struct prefix *)&api.prefix)) {
		char str1[128], str2[128];

		zlog_err("%s: function prefix mis-match %s and %s", __func__,
			 prefix2str(&locator->prefix, str1, sizeof(str1)),
			 prefix2str(&api.prefix, str2, sizeof(str2)));
		return;
	}
	if (prefix_same(&api.prefix, &addr_zero)) {
		struct prefix_ipv6 prefix = {
			.family = AF_INET6,
			.prefix = locator->prefix.prefix,
			.prefixlen = locator->prefix.prefixlen
				+ locator->function_bits_length,
		};
		uint64_t mask = ~((1ull << locator->function_bits_length) - 1);
		int retry_count = 0;

		do {
			locator->current += 1;
			if (locator->current & mask)
				locator->current = 0;
			get_function_addr(&prefix.prefix, locator->current,
					  128 - prefix.prefixlen);
			if (retry_count++ > 100) {
				zlog_err("%s: cannot get new function prefix",
					 __func__);
				return;
			}
		} while (zebra_srv6_function_lookup(locator, &prefix));
		api.prefix.prefix = prefix.prefix;
		api.prefix.prefixlen = prefix.prefixlen;
	}

	function = srv6_function_alloc(&api.prefix);
	*function = api;
	function->owner_proto = client->proto;
	function->owner_instance = client->instance;
	function->request_key = api.request_key;
	zebra_srv6_function_add(function, locator);
}

void zrecv_zebra_srv6_function_delete(ZAPI_HANDLER_ARGS)
{
	struct srv6_function api;
	struct srv6_locator *locator;
	struct srv6_function *function;

	zapi_srv6_function_decode(msg, &api);
	locator = zebra_srv6_locator_lookup(api.locator_name);
	if (!locator) {
		zlog_err("%s: locator '%s' is not found", __func__,
			 api.locator_name);
		return;
	}
	function = zebra_srv6_function_lookup(locator, &api.prefix);
	if (!function) {
		zlog_err("%s: function not found", __func__);
		return;
	}
	function->request_key = api.request_key;
	zebra_srv6_function_delete(function, locator);
	srv6_function_free(function);
}

void zebra_srv6_locator_update_all(struct zserv *client)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		zsend_zebra_srv6_locator_add(client, locator);
}

struct zebra_srv6 *zebra_srv6_get_default(void)
{
	static struct zebra_srv6 srv6;
	static bool first_execution = true;

	if (first_execution) {
		first_execution = false;
		srv6.locators = list_new();
	}
	return &srv6;
}

/**
 * Core function, assigns srv6-locator chunks
 *
 * It first searches through the list to check if there's one available
 * (previously released). Otherwise it creates and assigns a new one
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id SessionID of client
 * @param name Name of SRv6-locator
 * @return Pointer to the assigned srv6-locator chunk,
 *         or NULL if the request could not be satisfied
 */
static struct srv6_locator *
assign_srv6_locator_chunk(uint8_t proto,
			  uint16_t instance,
			  uint32_t session_id,
			  const char *locator_name)
{
	marker_debug_msg("call");

	struct srv6_locator *loc = NULL;
	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc) {
		zlog_info("%s: locator %s was not found",
			  __func__, locator_name);
		// TODO(slankdev): allocate dummy locator and set status down.
		return NULL;
	}

	bool chunk_found = false;
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		if (chunk->owner_proto != 0 && chunk->owner_proto != proto)
			continue;
		chunk_found = true;
		break;
	}

	if (!chunk_found) {
		zlog_info("%s: locator is already owned", __func__);
		return NULL;
	}

	chunk->owner_proto = proto;
	return loc;
}

static int
zebra_srv6_manager_get_locator_chunk(struct srv6_locator **loc,
				     struct zserv *client,
				     const char *locator_name,
				     vrf_id_t vrf_id)
{
	marker_debug_msg("call");
	*loc = assign_srv6_locator_chunk(client->proto, client->instance,
					 client->session_id, locator_name);

	if (!*loc)
		zlog_err("Unable to assign SRv6 locator chunk to %s instance %u",
			 zebra_route_string(client->proto), client->instance);
	else if (IS_ZEBRA_DEBUG_PACKET)
		zlog_info("Assigned SRv6 locator chunk %s to %s instance %u",
			  (*loc)->name, zebra_route_string(client->proto),
			  client->instance);

	return zsend_srv6_manager_get_locator_chunk_response(client, vrf_id, *loc);
}

static int zebra_srv6_manager_release_locator_chunk(struct zserv *client,
						    const char *locator_name,
						    vrf_id_t vrf_id)
{
	marker_debug_msg("call");

	struct srv6_locator *loc = NULL;
	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc) {
		return -1;
	}

	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		if (chunk->owner_proto != client->proto)
			continue;
		chunk->owner_proto = 0;
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_info("Released SRv6 locator chunk %s to %s instance %u",
			  loc->name, zebra_route_string(client->proto),
			  client->instance);

	return 0;
}

void zebra_srv6_init(void)
{
	hook_register(zserv_client_close, zebra_srv6_cleanup);
	hook_register(srv6_manager_get_chunk, zebra_srv6_manager_get_locator_chunk);
	hook_register(srv6_manager_release_chunk, zebra_srv6_manager_release_locator_chunk);
}

bool zebra_srv6_is_enable(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	return listcount(srv6->locators);
}
