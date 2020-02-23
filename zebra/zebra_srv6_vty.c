/*
 * Zebra SRv6 VTY functions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
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
#include "zebra/zebra_srv6_vty.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_dplane.h"
#include "zebra/ge_netlink.h"


static struct cmd_node sr_node = {
	SR_NODE, "%s(config-sr)# ", 1
};

static struct cmd_node srv6_node = {
	SRV6_NODE, "%s(config-srv6)# ", 1
};

static struct cmd_node srv6_locs_node = {
	SRV6_LOCS_NODE, "%s(config-srv6-locators)# ", 1
};

static struct cmd_node srv6_loc_node = {
	SRV6_LOC_NODE, "%s(config-srv6-locator)# ", 1
};

DEFUN (show_srv6_sid,
       show_srv6_sid_cmd,
       "show segment-routing srv6 sid [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "SID Information\n"
       JSON_STR)
{
	const bool uj = use_json(argc, argv);
	struct route_node *rn;
	struct route_table *table;
	json_object *json = NULL;
	json_object *json_sids = NULL;
	json_object *json_sid = NULL;

	if (uj) {
		json = json_object_new_object();
		json_sids = json_object_new_array();
		json_object_object_add(json, "localSids", json_sids);
	} else {
		vty_out(vty, "Local SIDs:\n");
		vty_out(vty, " Name       Context              Prefix                   Owner\n");
		vty_out(vty, "---------- -------------------- ------------------------ ------------\n");
	}

	table = zebra_vrf_table(AFI_IP6, SAFI_UNICAST, VRF_DEFAULT);

	for (rn = route_top(table);
	     rn; rn = srcdest_route_next(rn)) {
		struct route_entry *re;

		RNODE_FOREACH_RE (rn, re) {
			struct nexthop_group *nhg = re->nhe->nhg;
			struct nexthop *nexthop;
			char str1[128], str2[128];
			uint32_t action;

			for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
				if (!nexthop->nh_seg6local_ctx)
					continue;

				seg6local_context2str(str1, sizeof(str1),
					nexthop->nh_seg6local_ctx,
					nexthop->nh_seg6local_action);
				srcdest_rnode2str(rn, str2, sizeof(str2));
				action = nexthop->nh_seg6local_action;

				if (uj) {
					json_sid = json_object_new_object();
					json_object_string_add(
						json_sid, "name",
						seg6local_action2str(action));
					json_object_string_add(
						json_sid, "context", str1);
					json_object_string_add(
						json_sid, "prefix", str2);
					json_object_string_add(
						json_sid, "owner",
						zebra_route_string(re->type));
					json_object_array_add(
						json_sids, json_sid);
				} else
					vty_out(vty,
						" %-10s %-20s %-24s %-12s\n",
						seg6local_action2str(action),
						str1, str2,
						zebra_route_string(re->type));
			}
		}
	}

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(json,
					JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_srv6_locator,
       show_srv6_locator_cmd,
       "show segment-routing srv6 locator [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "Locator Information\n"
       JSON_STR)
{
	const bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;
	char str[256];
	int id;
	json_object *json = NULL;
	json_object *json_locators = NULL;
	json_object *json_locator = NULL;

	if (uj) {
		json = json_object_new_object();
		json_locators = json_object_new_array();
		json_object_object_add(json, "locators", json_locators);

		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			prefix2str(&locator->prefix, str, sizeof(str));
			json_locator = json_object_new_object();
			json_object_string_add(json_locator, "name",
					       locator->name);
			json_object_string_add(json_locator, "prefix", str);
			json_object_array_add(json_locators, json_locator);
		}

		vty_out(vty, "%s\n", json_object_to_json_string_ext(json,
					JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		vty_out(vty, "Locator:\n");
		vty_out(vty, "Name                 ID      Prefix                   Status\n");
		vty_out(vty, "-------------------- ------- ------------------------ -------\n");

		id = 1;
		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			prefix2str(&locator->prefix, str, sizeof(str));
			vty_out(vty, "%-20s %7d %-24s Up\n",
				locator->name, id, str);
			++id;
		}
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN_NOSH (segment_routing,
            segment_routing_cmd,
            "segment-routing",
            "Segment Routing\n")
{
	vty->node = SR_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6,
            srv6_cmd,
            "srv6",
            "Segment Routing SRv6\n")
{
	vty->node = SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locators,
            srv6_locators_cmd,
            "locators",
            "Segment Routing SRv6 locators\n")
{
	vty->node = SRV6_LOCS_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locator,
            srv6_locator_cmd,
            "locator WORD",
            "Segment Routing SRv6 locator\n"
            "Specify locator-name\n")
{
	struct srv6_locator *locator = NULL;

	locator = zebra_srv6_locator_lookup(argv[1]->arg);
	if (locator) {
		VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator);
		return CMD_SUCCESS;
	}

	locator = srv6_locator_alloc(argv[1]->arg);
	if (!locator) {
		vty_out(vty, "%% Alloc failed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator);
	vty->node = SRV6_LOC_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (segment_routing_srv6_encap,
            segment_routing_srv6_encap_cmd,
            "encapsulation",
            "Segment Routing SRv6 encap\n")
{
	vty->node = SRV6_ENCAP_NODE;
	return CMD_SUCCESS;
}

DEFUN (encapsulation_source_address,
       encapsulation_source_address_cmd,
       "source-address X:X::X:X",
       "Configure srv6 tunnel source address\n"
       "Specify source address\n")
{
	struct prefix_ipv6 cp;
	int ret = str2prefix_ipv6(argv[1]->arg, &cp);
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
       "prefix X:X::X:X/M [func-bits (8-64)]",
       "Configure SRv6 locator prefix\n"
       "Specify SRv6 locator prefix\n"
       "Configure SRv6 locator function length in bits\n"
       "Specify SRv6 locator function length in bits\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct prefix_ipv6 prefix;
	uint8_t function_bits_length = 16;
	int ret;

	ret = str2prefix_ipv6(argv[1]->arg, &prefix);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	apply_mask_ipv6(&prefix);

	if (argc >= 3)
		function_bits_length = strtoul(argv[3]->arg, NULL, 10);

	locator->prefix = prefix;
	locator->function_bits_length = function_bits_length;
	zebra_srv6_locator_add(locator);
	return CMD_SUCCESS;
}

static int zebra_sr_config(struct vty *vty)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node;
	struct srv6_locator *locator;
	char str[256];

	vty_out(vty, "!\n");
	if (zebra_srv6_is_enable()) {
		vty_out(vty, "segment-routing\n");
		vty_out(vty, " srv6\n");
		inet_ntop(AF_INET6, &srv6->encap_src, str, sizeof(str));
		vty_out(vty, "  encapsulation\n");
		vty_out(vty, "   source-address %s\n", str);
		vty_out(vty, "  !\n");

		vty_out(vty, "  locators\n");
		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			inet_ntop(AF_INET6, &locator->prefix.prefix,
				  str, sizeof(str));
			vty_out(vty, "   locator %s\n", locator->name);
			vty_out(vty, "    prefix %s/%u\n", str,
				locator->prefix.prefixlen);
			vty_out(vty, "   !\n");
		}
		vty_out(vty, "  !\n");

		if (srv6->vrf_ip.plist)
			vty_out(vty, "  pseudo-dt4-dummy-ip %s\n",
					prefix_list_name(srv6->vrf_ip.plist));
		vty_out(vty, " !\n");
		vty_out(vty, "!\n");
	}
	return 0;
}

void zebra_srv6_vty_init(void)
{
	/* Install nodes and its default commands */
	install_node(&sr_node, zebra_sr_config);
	install_node(&srv6_node, NULL);
	install_node(&srv6_locs_node, NULL);
	install_node(&srv6_loc_node, NULL);
	install_node(&srv6_encap_node, NULL);
	install_default(SR_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);
	install_default(SRV6_ENCAP_NODE);

	/* Command for change node */
	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SR_NODE, &srv6_cmd);
	install_element(SRV6_NODE, &srv6_locators_cmd);
	install_element(SRV6_LOCS_NODE, &srv6_locator_cmd);
	install_element(SRV6_NODE, &segment_routing_srv6_encap_cmd);

	/* Command for configuration */
	install_element(SRV6_LOC_NODE, &locator_prefix_cmd);
	install_element(SRV6_ENCAP_NODE, &encapsulation_source_address_cmd);
	install_element(SRV6_NODE, &pseudo_dt4_dummy_ip_cmd);

	/* Command for operation */
	install_element(VIEW_NODE, &show_srv6_sid_cmd);
	install_element(VIEW_NODE, &show_srv6_locator_cmd);
}
