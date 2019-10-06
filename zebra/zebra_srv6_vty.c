/* Zebra SRv6 VTY functions
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

#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "nexthop.h"
#include "vrf.h"
#include "srv6.h"
#include "lib/json.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_dplane.h"
#include "zebra/ge_netlink.h"


DEFUN (show_segment_routing_ipv6_sid,
       show_segment_routing_ipv6_sid_cmd,
       "show segment-routing-ipv6 sid",
       SHOW_STR
       "Segment-Routing IPv6\n"
       "SID Information\n")
{
	vty_out(vty, "Local SIDs:\n");
	vty_out(vty, " Name       Context              Prefix                   Owner      \n");
	vty_out(vty, "---------- -------------------- ------------------------ ------------\n");

	struct route_table *table;
	table = zebra_vrf_table(AFI_IP6, SAFI_UNICAST, VRF_DEFAULT);

	for (struct route_node *rn = route_top(table);
			 rn; rn = srcdest_route_next(rn)) {

		struct route_entry *re;
		RNODE_FOREACH_RE (rn, re) {
			struct nexthop_group *nhg = re->nhe->nhg;
			struct nexthop *nexthop;
			for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
				if (nexthop->seg6local_action == 0)
					continue;

				char cstr[128], pstr[128];
				seg6local_context2str(cstr, 128,
						&nexthop->seg6local_ctx,
						nexthop->seg6local_action);
				srcdest_rnode2str(rn, pstr, 128);

				uint32_t action = nexthop->seg6local_action;
				vty_out(vty, " %-10s %-20s %-24s %-12s\n",
						seg6local_action2str(action), cstr, pstr,
						zebra_route_string(re->type));

			}
		}
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_segment_routing_ipv6_locator,
       show_segment_routing_ipv6_locator_cmd,
       "show segment-routing-ipv6 locator",
       SHOW_STR
       "Segment-Routing IPv6\n"
			 "Locator Information\n")
{
	struct srv6 *srv6 = srv6_get_default();
	char str[256];

	prefix2str(&srv6->locator, str, sizeof(str));
	vty_out(vty, "Locator:\n");
	vty_out(vty, "Name                 ID      Prefix                   Status\n");
	vty_out(vty, "-------------------- ------- ------------------------ -------\n");
	vty_out(vty, "default*             1       %-24s Up\n", str);
	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_segment_routing_ipv6_manager,
       show_segment_routing_ipv6_manager_cmd,
       "show segment-routing-ipv6 manager",
       SHOW_STR
       "Segment-Routing IPv6\n"
       "Manager Information\n")
{
	vty_out(vty, "\n");
	char str[256];
	struct srv6 *srv6 = srv6_get_default();

	inet_ntop(AF_INET6, &srv6->encap_src, str, sizeof(str));
	vty_out(vty, "SRv6 Encap Source: %s\n", str);
	vty_out(vty, "SRv6 pseudo End.DT4 vrf_ip prefix-list: %s\n",
			srv6->vrf_ip.plist ? prefix_list_name(srv6->vrf_ip.plist) : "n/a");
	vty_out(vty, "\n");

	vty_out(vty, "vrf-ip table:\n");
	for (struct route_node *rn = route_top(srv6->vrf_ip.table);
			 rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;
		char s[128];
		prefix2str(&rn->p, s, 128);
		vty_out(vty, "%s: %u\n", s, *(uint32_t*)rn->info);
	}

	return CMD_SUCCESS;
}

DEFUN (no_segment_routing_ipv6,
       no_segment_routing_ipv6_cmd,
       "no segment-routing-ipv6",
			 NO_STR
       "negate Segment Routing IPv6\n")
{
	struct srv6 *srv6 = srv6_get_default();
	srv6->is_enable = false;
	return CMD_SUCCESS;
}

/* "segment-routing-ipv6" commands. */
DEFUN_NOSH (segment_routing_ipv6,
       segment_routing_ipv6_cmd,
       "segment-routing-ipv6",
       "Segment Routing IPv6\n")
{
	struct srv6 *srv6 = srv6_get_default();
	srv6->is_enable = true;
	vty->node = SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN (encapsulation_source_address,
       encapsulation_source_address_cmd,
       "encapsulation source-address X:X::X:X",
       "Configure srv6 encapsulation\n"
			 "Configure srv6 tunnel source address\n"
			 "Specify source address\n")
{
	struct prefix_ipv6 cp;
	int ret = str2prefix_ipv6(argv[2]->arg, &cp);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address \n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	assert(cp.prefixlen == 128);

	struct zebra_ns *zns = zebra_ns_lookup(0);
	if (!zns) {
		vty_out(vty, "can't find zebra_ns\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	dplane_srtunsrc_update(&cp.prefix);

	struct srv6 *srv6 = srv6_get_default();
	srv6->is_enable = true;
	memcpy(&srv6->encap_src, &cp.prefix, sizeof(struct in6_addr));
	return CMD_SUCCESS;
}

DEFUN (pseudo_dt4_dummy_ip,
       pseudo_dt4_dummy_ip_cmd,
       "[no] pseudo-dt4-dummy-ip WORD",
			 NO_STR
       "Specify dummy-ip-range for pseudo End.DT4\n"
			 "Specify prefix-list-name\n")
{
	int idx = 0;
	bool negate = false;
	if (argv_find(argv, argc, "no", &idx))
		negate = true;

	struct srv6 *srv6 = srv6_get_default();
	if (negate) {
		vty_out(vty, "this command doesn't supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	const char *plist_name = argv[negate?2:1]->arg;
	struct prefix_list *plist = prefix_list_lookup(AFI_IP, plist_name);
	if (!plist) {
		vty_out(vty, "no such prefix-list (%s)\n", plist_name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	srv6->vrf_ip.plist = plist;
	return CMD_SUCCESS;
}

DEFUN (locator_prefix,
       locator_prefix_cmd,
       "locator prefix X:X::X:X/M",
       "Configure srv6 locator\n"
			 "Configure srv6 locator prefix\n"
			 "Specify prefix\n")
{
	struct prefix_ipv6 cp;
	int ret = str2prefix_ipv6(argv[2]->arg, &cp);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	zebra_srv6_locator_init(&cp);
	return CMD_SUCCESS;
}


/* SRv6 SID configuration write function. */
static int zebra_srv6_config(struct vty *vty)
{
	vty_out(vty, "!\n");
	struct srv6 *srv6 = srv6_get_default();
	if (srv6->is_enable) {
		vty_out(vty, "segment-routing-ipv6\n");
		char str[256];
		inet_ntop(AF_INET6, &srv6->encap_src, str, sizeof(str));
		vty_out(vty, " encapsulation source-address %s\n", str);

		inet_ntop(AF_INET6, &srv6->locator.prefix, str, sizeof(str));
		vty_out(vty, " locator prefix %s/%u\n",
				str, srv6->locator.prefixlen);

		if (srv6->vrf_ip.plist)
			vty_out(vty, " pseudo-dt4-dummy-ip %s\n",
					prefix_list_name(srv6->vrf_ip.plist));
		vty_out(vty, "!\n");
	}

	return 0;
}

/* SRv6 node structure. */
static struct cmd_node srv6_node = {SRV6_NODE, "%s(config-srv6)# ", 1};

/* SRv6 VTY.  */
void zebra_srv6_vty_init(void)
{
	install_element(VIEW_NODE, &show_segment_routing_ipv6_sid_cmd);
	install_element(VIEW_NODE, &show_segment_routing_ipv6_locator_cmd);
	install_element(VIEW_NODE, &show_segment_routing_ipv6_manager_cmd);

	install_node(&srv6_node, zebra_srv6_config);
	install_default(SRV6_NODE);

	install_element(CONFIG_NODE, &segment_routing_ipv6_cmd);
	install_element(CONFIG_NODE, &no_segment_routing_ipv6_cmd);
	install_element(SRV6_NODE, &encapsulation_source_address_cmd);
	install_element(SRV6_NODE, &locator_prefix_cmd);
	install_element(SRV6_NODE, &pseudo_dt4_dummy_ip_cmd);
}

