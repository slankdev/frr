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

#ifndef _QUAGGA_ZEBRA_SRV6_H
#define _QUAGGA_ZEBRA_SRV6_H

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
	struct prefix_ipv6 locator;
	struct pseudo_dt4_vrf_ip vrf_ip;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(srv6)

extern void zebra_srv6_init(void);
extern void zebra_srv6_vty_init(void);
extern void zebra_srv6_locator_init(const struct prefix_ipv6 *loc);
extern struct srv6 *srv6_get_default(void);

extern void zebra_srv6_get_locator(ZAPI_HANDLER_ARGS);
extern void zebra_srv6_alloc_sid(ZAPI_HANDLER_ARGS);

#endif /* _QUAGGA_ZEBRA_SEG6_H */
