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
#include "zebra/slankdev_netlink.h"
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

static int zapi_seg6_decode(struct stream *s, struct zapi_seg6 *api)
{
	STREAM_GETL(s, api->afi);
	stream_get(&api->pref4, s, 4);
	stream_get(&api->pref6, s, 16);
	STREAM_GETL(s, api->plen);
	STREAM_GETL(s, api->table_id);

	STREAM_GETL(s, api->mode);
	STREAM_GETL(s, api->num_segs);
	for (size_t i=0; i<api->num_segs; i++)
		stream_get(&api->segs[i], s, 16);
stream_failure:
	return 0;
}

#if 0
static struct ipv6_sr_hdr *parse_srh(bool encap,
    size_t num_segs, const struct in6_addr *segs)
{
  const size_t srhlen = 8 + sizeof(struct in6_addr)*(encap ? num_segs+1 : num_segs);

  struct ipv6_sr_hdr *srh = malloc(srhlen);
  memset(srh, 0, srhlen);
  srh->hdrlen = (srhlen >> 3) - 1;
  srh->type = 4;
  srh->segments_left = encap ? num_segs : num_segs - 1;
  srh->first_segment = encap ? num_segs : num_segs - 1;

  size_t srh_idx = encap ? 1 : 0;
  for (ssize_t i=num_segs-1; i>=0; i--)
    memcpy(&srh->segments[srh_idx + i], &segs[num_segs - 1 - i], sizeof(struct in6_addr));
  return srh;
}
#endif

static void adddel_in6_route(
    struct in6_addr *pref, uint32_t plen,
		struct in6_addr *nh6, bool install)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    exit(1);

	struct {
    struct nlmsghdr  n;
    struct rtmsg r;
    char buf[4096];
  } req = {
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
    .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
    .n.nlmsg_type = install ? RTM_NEWROUTE : RTM_DELROUTE,
    .r.rtm_family = AF_INET6,
    .r.rtm_dst_len = plen,
    .r.rtm_src_len = 0,
    .r.rtm_tos = 0,
    .r.rtm_table = RT_TABLE_MAIN,
    .r.rtm_protocol = 0x03,
    .r.rtm_scope = 0xfd,
    .r.rtm_type = RTN_UNICAST,
    .r.rtm_flags = 0,
  };

  /* set RTA_DST */
  addattr_l(&req.n, sizeof(req), RTA_DST, pref, sizeof(struct in6_addr));
  req.r.rtm_dst_len = plen;

  /* set RTA_GATEWAY */
  addattr_l(&req.n, sizeof(req), RTA_GATEWAY, nh6, sizeof(struct in6_addr));

  /* talk with netlink-bus */
  /* hexdump(stdout, &req.n, req.n.nlmsg_len); */
  if (nl_talk(fd, &req.n, NULL, 0) < 0)
    exit(1);
	close(fd);
}

static void adddel_in4_seg6_route(
    struct in_addr *pref, uint32_t plen, uint32_t mode,
		uint32_t num_segs, const struct in6_addr *segs,
    uint32_t oif_idx, uint32_t table_id,
		bool install)
{
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    exit(1);

  struct {
    struct nlmsghdr  n;
    struct rtmsg r;
    char buf[4096];
  } req = {
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
    .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
    .n.nlmsg_type = install ? RTM_NEWROUTE : RTM_DELROUTE,
    .r.rtm_family = AF_INET,
    .r.rtm_dst_len = plen,
    .r.rtm_src_len = 0,
    .r.rtm_tos = 0,
    .r.rtm_table = table_id,
    .r.rtm_protocol = 0x03,
    .r.rtm_scope = 0xfd,
    .r.rtm_type = RTN_UNICAST,
    .r.rtm_flags = 0,
  };

  /* set RTA_DST */
  addattr_l(&req.n, sizeof(req), RTA_DST, pref, sizeof(struct in_addr));
  req.r.rtm_dst_len = plen;

  /* set RTA_OIF */
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);

  /* set RTA_ENCAP */
  char buf[1024];
  struct rtattr *rta = (void *)buf;
  rta->rta_type = RTA_ENCAP;
  rta->rta_len = RTA_LENGTH(0);
  struct rtattr *nest = rta_nest(rta, sizeof(buf), RTA_ENCAP);
  struct ipv6_sr_hdr *srh = parse_srh(false, num_segs, segs);
  size_t srhlen = (srh->hdrlen + 1) << 3;
  struct seg6_iptunnel_encap *tuninfo = malloc(sizeof(*tuninfo) + srhlen);
  memset(tuninfo, 0, sizeof(*tuninfo) + srhlen);
  memcpy(tuninfo->srh, srh, srhlen);
  tuninfo->mode = SEG6_IPTUN_MODE_ENCAP;
  rta_addattr_l(rta, sizeof(buf), SEG6_IPTUNNEL_SRH,
      tuninfo, sizeof(*tuninfo) + srhlen);
  rta_nest_end(rta, nest);
  addraw_l(&req.n, 1024 , RTA_DATA(rta), RTA_PAYLOAD(rta));

  /* set RTA_ENCAP_TYPE */
  addattr16(&req.n, sizeof(req), RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6);

  hexdump(stdout, &req.n, req.n.nlmsg_len);
  if (nl_talk(fd, &req.n, NULL, 0) < 0)
    exit(1);

  close(fd);
}

static void add_seg6local_end_route(
    struct in6_addr *pref, uint32_t plen,
    uint32_t oif_idx, bool install)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    exit(1);

  struct {
    struct nlmsghdr  n;
    struct rtmsg r;
    char buf[4096];
  } req = {
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
    .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
    .n.nlmsg_type = install ? RTM_NEWROUTE : RTM_DELROUTE,
    .r.rtm_family = AF_INET6,
    .r.rtm_dst_len = plen,
    .r.rtm_src_len = 0,
    .r.rtm_tos = 0,
    .r.rtm_table = RT_TABLE_MAIN,
    .r.rtm_protocol = 0x03,
    .r.rtm_scope = 0xfd,
    .r.rtm_type = RTN_UNICAST,
    .r.rtm_flags = 0,
  };

  /* set RTA_DST */
  addattr_l(&req.n, sizeof(req), RTA_DST, pref, sizeof(struct in6_addr));
  req.r.rtm_dst_len = plen;

  /* set RTA_OIF */
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);

  /* set RTA_ENCAP */
  char buf[1024];
  struct rtattr *rta = (void *)buf;
  rta->rta_type = RTA_ENCAP;
  rta->rta_len = RTA_LENGTH(0);
  struct rtattr *nest = rta_nest(rta, sizeof(buf), RTA_ENCAP);
  rta_addattr32(rta, sizeof(buf), SEG6_LOCAL_ACTION, SEG6_LOCAL_ACTION_END);
  rta_nest_end(rta, nest);
  addraw_l(&req.n, 1024 , RTA_DATA(rta), RTA_PAYLOAD(rta));

  /* set RTA_ENCAP_TYPE */
  addattr16(&req.n, sizeof(req), RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6_LOCAL);

  hexdump(stdout, &req.n, req.n.nlmsg_len);
  if (nl_talk(fd, &req.n, NULL, 0) < 0)
    exit(1);

	close(fd);
}

static void add_seg6local_end_dx4_route(
    struct in6_addr *pref, uint32_t plen,
    uint32_t oif_idx, struct in_addr *nh4,
		bool install)
{
#if 0
	if (true) {
		char str[128];
		inet_ntop(AF_INET6, pref, str, 128);
		marker_debug();
		zlog_debug(C_YEL "%s: install=%s sid=%s" C_DEF,
				__func__, install?"true":"false", str);
	}
#endif

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    exit(1);

  struct {
    struct nlmsghdr  n;
    struct rtmsg r;
    char buf[4096];
  } req = {
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
    .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
    .n.nlmsg_type = install ? RTM_NEWROUTE : RTM_DELROUTE,
    .r.rtm_family = AF_INET6,
    .r.rtm_dst_len = plen,
    .r.rtm_src_len = 0,
    .r.rtm_tos = 0,
    .r.rtm_table = RT_TABLE_MAIN,
    .r.rtm_protocol = 0x03,
    .r.rtm_scope = 0xfd,
    .r.rtm_type = RTN_UNICAST,
    .r.rtm_flags = 0,
  };

  /* set RTA_DST */
  addattr_l(&req.n, sizeof(req), RTA_DST, pref, sizeof(struct in6_addr));
  req.r.rtm_dst_len = plen;

  /* set RTA_OIF */
  addattr32(&req.n, sizeof(req), RTA_OIF, oif_idx);

  /* set RTA_ENCAP */
  char buf[1024];
  struct rtattr *rta = (void *)buf;
  rta->rta_type = RTA_ENCAP;
  rta->rta_len = RTA_LENGTH(0);
  struct rtattr *nest = rta_nest(rta, sizeof(buf), RTA_ENCAP);
  rta_addattr32(rta, sizeof(buf), SEG6_LOCAL_ACTION, SEG6_LOCAL_ACTION_END_DX4);
	rta_addattr_l(rta, sizeof(buf), SEG6_LOCAL_NH4, nh4, sizeof(struct in_addr));
  rta_nest_end(rta, nest);
  addraw_l(&req.n, 1024 , RTA_DATA(rta), RTA_PAYLOAD(rta));

  /* set RTA_ENCAP_TYPE */
  addattr16(&req.n, sizeof(req), RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6_LOCAL);

  hexdump(stdout, &req.n, req.n.nlmsg_len);
  if (nl_talk(fd, &req.n, NULL, 0) < 0)
    exit(1);

	close(fd);
}

const char* seg6local_action2str(uint32_t action)
{
	switch (action) {
	case SEG6_LOCAL_ACTION_END: return "End";
  case SEG6_LOCAL_ACTION_END_X: return "End.X";
  case SEG6_LOCAL_ACTION_END_T: return "End.T";
	case SEG6_LOCAL_ACTION_END_DX2: return "End.DX2";
  case SEG6_LOCAL_ACTION_END_DX6: return "End.DX6";
  case SEG6_LOCAL_ACTION_END_DX4: return "End.DX4";
  case SEG6_LOCAL_ACTION_END_DT6: return "End.DT6";
  case SEG6_LOCAL_ACTION_END_DT4: return "End.DT4";
  case SEG6_LOCAL_ACTION_END_B6: return "End.B6";
	case SEG6_LOCAL_ACTION_END_B6_ENCAP: return "End.B6.Encap";
	case SEG6_LOCAL_ACTION_END_BM: return "End.BM";
  case SEG6_LOCAL_ACTION_END_S: return "End.S";
  case SEG6_LOCAL_ACTION_END_AS: return "End.AS";
  case SEG6_LOCAL_ACTION_END_AM: return "End.AM";

	case SEG6_LOCAL_ACTION_UNSPEC:
	default:
		printf("ABORT...\n");
		abort();
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

static int del_seg6local_sid(const struct in6_addr *pref,
		uint32_t plen, uint32_t action, void *args)
{
	for (size_t i=0; i<MAX_SEG6LOCAL_SIDS; i++) {
		if (!seg6local_sids[i])
			continue;

		if ((seg6local_sids[i]->plen == plen)
		 && (memcmp(&seg6local_sids[i]->sid, pref, plen) == 0)) {
			struct seg6local_sid *tmp = seg6local_sids[i];
			free(tmp);
			return i;
		}
	}

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

void zebra_seg6local_add(ZAPI_HANDLER_ARGS)
{
	struct zapi_seg6local api;
	struct stream *s = msg;
	memset(&api, 0, sizeof(struct zapi_seg6local));
	if (zapi_seg6local_decode(s, &api) < 0) {
		printf("%s: Unable to decode zapi_route sent",
				 __PRETTY_FUNCTION__);
		return;
	}

#if 1
	/* DUMP API structure */
	zapi_seg6local_dump(stdout, &api);
#endif

	const uint32_t dummy_oif = 2;
	add_seg6local_sid(&api.sid, api.plen, api.action, &api, api.owner);
	frr_with_privs(&zserv_privs) {
		switch (api.action) {
			case SEG6_LOCAL_ACTION_END:
				add_seg6local_end_route(&api.sid, api.plen, dummy_oif, true);
				break;
			case SEG6_LOCAL_ACTION_END_DX4:
				add_seg6local_end_dx4_route(&api.sid, api.plen, dummy_oif, &api.nh4, true);
				break;
			default:
				abort();
				break;
		}
	}
}

void zebra_seg6local_delete(ZAPI_HANDLER_ARGS)
{
	struct zapi_seg6local api;
	struct stream *s = msg;
	memset(&api, 0, sizeof(struct zapi_seg6local));
	if (zapi_seg6local_decode(s, &api) < 0) {
		printf("%s: Unable to decode zapi_route sent",
				 __PRETTY_FUNCTION__);
		return;
	}

#if 1
	/* DUMP API structure */
	zapi_seg6local_dump(stdout, &api);
#endif

	del_seg6local_sid(&api.sid, api.plen, 0, NULL);

	const uint32_t dummy_oif = 2;
	frr_with_privs(&zserv_privs) {
		switch (api.action) {
			case SEG6_LOCAL_ACTION_END:
				add_seg6local_end_route(&api.sid, api.plen, dummy_oif, false);
				break;
			case SEG6_LOCAL_ACTION_END_DX4:
				add_seg6local_end_dx4_route(&api.sid, api.plen, dummy_oif, &api.nh4, false);
				break;
			default:
				abort();
				break;
		}
	}
}

void zebra_seg6_add(ZAPI_HANDLER_ARGS)
{
	struct zapi_seg6 api;
	memset(&api, 0, sizeof(api));
	zapi_seg6_decode(msg, &api);

#if 1
	/* DUMP API structure */
	zapi_seg6_dump(stdout, &api);
#endif

	const uint32_t dummy_oif = 2;
	frr_with_privs(&zserv_privs) {
		adddel_in4_seg6_route(&api.pref4, api.plen, api.mode,
				api.num_segs, api.segs, dummy_oif, api.table_id, true);
	}
}

void zebra_seg6_delete(ZAPI_HANDLER_ARGS)
{
	struct zapi_seg6 api;
	memset(&api, 0, sizeof(api));
	zapi_seg6_decode(msg, &api);

#if 1
	/* DUMP API structure */
	zapi_seg6_dump(stdout, &api);
#endif

	const uint32_t dummy_oif = 2;
	frr_with_privs(&zserv_privs) {
		adddel_in4_seg6_route(&api.pref4, api.plen, api.mode,
				api.num_segs, api.segs, dummy_oif, api.table_id, false);
	}
}

void zebra_srv6_sid_route_add(ZAPI_HANDLER_ARGS)
{
	struct zapi_seg6local api;
	memset(&api, 0, sizeof(api));
	zapi_seg6local_decode(msg, &api);

#if 0
	/* DUMP API structure */
	zapi_seg6_dump(stdout, &api);
#endif

	frr_with_privs(&zserv_privs) {
		adddel_in6_route(&api.sid, api.plen, &api.nh6, true);
	}
}

void zebra_srv6_sid_route_delete(ZAPI_HANDLER_ARGS)
{
	struct zapi_seg6local api;
	memset(&api, 0, sizeof(api));
	zapi_seg6local_decode(msg, &api);

#if 0
	/* DUMP API structure */
	zapi_seg6_dump(stdout, &api);
#endif

	frr_with_privs(&zserv_privs) {
		adddel_in6_route(&api.sid, api.plen, &api.nh6, false);
	}
}

void zebra_srv6_init()
{
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
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}
