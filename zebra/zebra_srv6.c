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

struct srv6 *srv6_get_default(void)
{
	static struct srv6 srv6;
	static bool first_execution = true;
	if (first_execution) {
		srv6.is_enable = false;
		first_execution = false;
	}
	return &srv6;
}

void zebra_srv6_init()
{
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

	struct prefix p;
	memset(&p, 0, sizeof(p));
	memcpy(&p.u.prefix6, &api.sid, 16);
	p.family = AF_INET6;
	p.prefixlen = 128;
	seg6local_add_end(&p);
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
