/* BGP message definition header.
 * Copyright (C) 2019 Hiroki Shirokura
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "zebra/zserv.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_errors.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/seg6_iptunnel.h>
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

extern struct zebra_privs_t zserv_privs;
struct seg6local_sid *seg6local_sids[MAX_SEG6LOCAL_SIDS];
static uint16_t sid_allocate_next = 0x10;

static void seg6local_add_end(struct prefix *prefix)
{
	struct route_entry *re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = ZEBRA_ROUTE_STATIC;
	re->instance = 0;
	SET_FLAG(re->flags, ZEBRA_FLAG_SEG6LOCAL_ROUTE);
	re->uptime = monotime(NULL);
	re->vrf_id = VRF_DEFAULT;
	re->table = RT_TABLE_MAIN;

	struct in6_addr ipv6;
	memset(&ipv6, 0, sizeof(ipv6));
	ifindex_t ifindex = 2; //TODO(slankdev): this dummy number.... :(

	struct nexthop *nexthop =
		route_entry_nexthop_ifindex_add(
			re, ifindex, VRF_DEFAULT);

	if (!nexthop) {
			flog_warn(
				EC_ZEBRA_NEXTHOP_CREATION_FAILED,
				"%s: Nexthops Specified: but we failed to properly create one",
				__PRETTY_FUNCTION__);
		nexthops_free(re->ng.nexthop);
		XFREE(MTYPE_RE, re);
		return;
	}

	struct seg6local_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	nexthop_add_seg6local(nexthop, SEG6_LOCAL_ACTION_END, &ctx);

	int ret = rib_add_multipath(AFI_IP6, SAFI_UNICAST, prefix, NULL, re);
	if (ret < 0)  {
		zlog_err("%s: can't add RE entry to rib", __func__);
	}
}

int
snprintf_seg6local_sid(char *str, size_t size,
		const struct seg6local_sid *sid)
{
	char buf[128];
	inet_ntop(AF_INET6, &sid->sid, buf, sizeof(buf));
	return snprintf(str, size,
			"ipv6 route %s/%u encap seg6local action %s",
			buf, sid->plen, seg6local_action2str(sid->action));
}

int
snprintf_seg6local_context(char *str, size_t size,
		const struct seg6local_sid *sid)
{
	char b0[128];
	memset(str, 0, size);
	switch (sid->action) {

		case SEG6_LOCAL_ACTION_END:
			return snprintf(str, size, "USP");

		case SEG6_LOCAL_ACTION_END_X:
		case SEG6_LOCAL_ACTION_END_DX6:
			inet_ntop(AF_INET6, &sid->context.nh6, b0, 128);
			return snprintf(str, size, "nh6 %s", b0);

		case SEG6_LOCAL_ACTION_END_DX4:
			inet_ntop(AF_INET, &sid->context.nh4, b0, 128);
			return snprintf(str, size, "nh4 %s", b0);

		case SEG6_LOCAL_ACTION_END_T:
		case SEG6_LOCAL_ACTION_END_DT6:
		case SEG6_LOCAL_ACTION_END_DT4:
			return snprintf(str, size, "table %u", sid->context.table);

		case SEG6_LOCAL_ACTION_END_DX2:
		case SEG6_LOCAL_ACTION_END_B6:
		case SEG6_LOCAL_ACTION_END_B6_ENCAP:
		case SEG6_LOCAL_ACTION_END_BM:
		case SEG6_LOCAL_ACTION_END_S:
		case SEG6_LOCAL_ACTION_END_AS:
		case SEG6_LOCAL_ACTION_END_AM:
		case SEG6_LOCAL_ACTION_UNSPEC:
		default:
			return snprintf(str, size, "unknown(%s)", __func__);
	}
}

static int add_seg6local_sid(const struct in6_addr *pref,
		uint32_t plen, uint32_t action, struct zapi_seg6local *api, uint32_t owner)
{
	struct seg6local_sid *sid =
		(struct seg6local_sid*)malloc(sizeof(struct seg6local_sid));
	memcpy(&sid->sid, pref, sizeof(struct in6_addr));
	sid->plen = plen;
	sid->action = action;
	sid->owner = owner;

	/* fill sid->context */
	memcpy(&sid->context.nh4, &api->nh4, 4);
	memcpy(&sid->context.nh6, &api->nh6, 16);
	sid->context.table = api->table;

	for (size_t i=0; i<MAX_SEG6LOCAL_SIDS; i++) {
		if (!seg6local_sids[i])
			continue;

		if ((seg6local_sids[i]->plen == plen)
		 && (memcmp(&seg6local_sids[i]->sid, pref, plen) == 0)) {
			struct seg6local_sid *tmp = seg6local_sids[i];
			seg6local_sids[i] = sid;
			free(tmp);
			return i;
		}
	}

	for (size_t i=0; i<MAX_SEG6LOCAL_SIDS; i++) {
		if (!seg6local_sids[i]) {
			seg6local_sids[i] = sid;
			return i;
		}
	}

	free(sid);
	return -1;
}

size_t num_seg6local_sids(void)
{
	size_t num = 0;
	for (size_t i=0; i<MAX_SEG6LOCAL_SIDS; i++) {
		if (seg6local_sids[i])
			num ++;
	}
	return num;
}

void zebra_srv6_init()
{
	memset(seg6local_sids, 0, sizeof(seg6local_sids));
}

void zebra_srv6_get_locator(ZAPI_HANDLER_ARGS)
{
	struct srv6 *srv6 = srv6_get_default();
	uint16_t preflen = srv6->locator.prefixlen;
	struct in6_addr *prefix6 = &srv6->locator.prefix;

	/* Create Response Msg */
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zclient_create_header(s, ZEBRA_SRV6_GET_LOCATOR, 0);
	stream_putw(s, preflen);
	stream_put(s, prefix6, 16);
	stream_putw_at(s, 0, stream_get_endp(s));

	/* Send Response Msg */
	int ret = writen(client->sock, s->data, stream_get_endp(s));
	stream_free(s);
	if (ret < 0)
		zlog_err("%s: error occured", __func__);
}

void zebra_srv6_alloc_sid(ZAPI_HANDLER_ARGS)
{
	/* Generate NEW SID */
	struct in6_addr sid;
	struct srv6 *srv6 = srv6_get_default();
	const struct in6_addr *loc = &srv6->locator.prefix;
	memcpy(&sid, loc, sizeof(struct in6_addr));
	sid.s6_addr16[7] = htons(sid_allocate_next++);

	char str[128];
	inet_ntop(AF_INET6, &sid, str, 128);
	zlog_info("%s: Allocate new sid %s", __func__, str);

	/* Create Response Msg */
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zclient_create_header(s, ZEBRA_SRV6_ALLOC_SID, 0);
	stream_put(s, &sid, 16);
	stream_put(s, &srv6->locator, sizeof(struct prefix_ipv6));
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zebra_srv6_locator_init(
		const struct prefix_ipv6 *loc)
{
	struct srv6 *srv6 = srv6_get_default();
	srv6->is_enable = true;
	memcpy(&srv6->locator, loc, sizeof(*loc));

	/* Allocate End for SID-manager */
	struct zapi_seg6local api = {0};
	memcpy(&api.sid, &loc->prefix, 16);
	api.sid.s6_addr16[7] = htons(1);
	api.plen = 128;
	api.action = SEG6_LOCAL_ACTION_END;
	api.owner = ZEBRA_ROUTE_SYSTEM;
	add_seg6local_sid(&api.sid, api.plen, api.action, &api, api.owner);

	struct prefix p;
	memset(&p, 0, sizeof(p));
	memcpy(&p.u.prefix6, &api.sid, 16);
	p.family = AF_INET6;
	p.prefixlen = 128;
	seg6local_add_end(&p);
}
