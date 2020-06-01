/*
 * Zebra SRv6 definitions
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

#ifndef _ZEBRA_SRV6_H
#define _ZEBRA_SRV6_H

#include <zebra.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "qobj.h"
#include "prefix.h"
#include <pthread.h>
#include <plist.h>

struct pseudo_dt4_vrf_ip {
	struct prefix_list *plist;
	struct route_table *table;
};

/* SRv6 instance structure.  */
struct srv6 {
	bool is_enable;
	struct in6_addr encap_src;
	struct list *locators;
	struct pseudo_dt4_vrf_ip vrf_ip;
};

extern void zebra_srv6_locator_add(struct srv6_locator *locator);
extern void zebra_srv6_locator_delete(struct srv6_locator *locator);
extern struct srv6_locator *zebra_srv6_locator_lookup(const char *name);

extern void zebra_srv6_function_add(
		struct srv6_function *function,
		struct srv6_locator *locator);
extern void zebra_srv6_function_delete(
		struct srv6_function *function,
		struct srv6_locator *locator);
extern struct srv6_function *zebra_srv6_function_lookup(
		const struct srv6_locator *locator,
		const struct prefix_ipv6 *prefix);
extern void zrecv_zebra_srv6_function_add(ZAPI_HANDLER_ARGS);
extern void zrecv_zebra_srv6_function_delete(ZAPI_HANDLER_ARGS);

extern void zebra_srv6_init(void);
extern void zebra_srv6_locator_update_all(struct zserv *client);
extern struct srv6 *srv6_get_default(void);

#endif /* _ZEBRA_SRV6_H */
