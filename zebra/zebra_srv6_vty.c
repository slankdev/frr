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
#include "zebra/zebra_srv6_vty.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_dplane.h"


static struct cmd_node sr_node = {SR_NODE, "%s(config-sr)# ", 1};
static struct cmd_node srv6_node = {SRV6_NODE, "%s(config-srv6)# ", 1};
static struct cmd_node srv6_locs_node = {SRV6_LOCS_NODE, "%s(config-srv6-locators)# ", 1};
static struct cmd_node srv6_loc_node = {SRV6_LOC_NODE, "%s(config-srv6-locator)# ", 1};


DEFUN_NOSH (segment_routing,
            segment_routing_cmd,
            "segment-routing",
            "Segment Routing\n")
{
	vty->node = SR_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (segment_routing_srv6,
            segment_routing_srv6_cmd,
            "srv6",
            "Segment Routing SRv6\n")
{
	vty->node = SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (segment_routing_srv6_locators,
            segment_routing_srv6_locators_cmd,
            "locators",
            "Segment Routing SRv6 locators\n")
{
	vty->node = SRV6_LOCS_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (segment_routing_srv6_locators_locator,
            segment_routing_srv6_locators_locator_cmd,
            "locator WORD",
            "Segment Routing SRv6 locator\n"
            "Specify locator-name\n")
{
	vty->node = SRV6_LOC_NODE;
	return CMD_SUCCESS;
}

static int zebra_sr_config(struct vty *vty)
{
	return 0;
}

void zebra_srv6_vty_init(void)
{
	/* Install nodes and its default commands */
	install_node(&sr_node, zebra_sr_config);
	install_node(&srv6_node, NULL);
	install_node(&srv6_locs_node, NULL);
	install_node(&srv6_loc_node, NULL);
	install_default(SR_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);

	/* Command for change node */
	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SR_NODE, &segment_routing_srv6_cmd);
	install_element(SRV6_NODE, &segment_routing_srv6_locators_cmd);
	install_element(SRV6_LOCS_NODE, &segment_routing_srv6_locators_locator_cmd);
}
