/*
 * Static SRv6 definitions
 * Copyright (C) 2020  Masakazu Asama
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

#ifndef _STATIC_SRV6_H
#define _STATIC_SRV6_H

#include "linklist.h"
#include "prefix.h"
#include "zclient.h"


extern void static_srv6_locator_add(struct srv6_locator *locator);
extern void static_srv6_locator_delete(struct srv6_locator *locator);
extern struct srv6_locator *static_srv6_locator_lookup(const char *name);

extern void static_srv6_function_add(struct srv6_function *function, struct srv6_locator *locator);
extern void static_srv6_function_delete(struct srv6_function *function, struct srv6_locator *locator);
extern struct srv6_function *static_srv6_function_lookup(const struct srv6_locator *locator, const struct prefix_ipv6 *prefix);
extern struct srv6_function *static_srv6_function_find_by_request_key(const struct srv6_locator *locator, const uint32_t request_key);

extern struct list *static_srv6_locators(void);
extern int static_srv6_config(struct vty *vty);
extern void static_srv6_init(void);

#endif /* _STATIC_SRV6_H */
