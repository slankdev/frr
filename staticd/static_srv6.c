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

#include <zebra.h>

#include "command.h"
#include "linklist.h"

#include "staticd/static_memory.h"
#include "staticd/static_srv6.h"
#include "staticd/static_zebra.h"

DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6, "Static SRv6");

static struct list *srv6_locators;

/*
 * locator
 */

void static_srv6_locator_add(struct srv6_locator *locator)
{
	listnode_add(srv6_locators, locator);
}

void static_srv6_locator_delete(struct srv6_locator *locator)
{
	listnode_delete(srv6_locators, locator);
}

struct srv6_locator *static_srv6_locator_lookup(const char *name)
{
	struct srv6_locator *locator;
	struct listnode *node;
	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node, locator)) {
		if (!strncmp(name, locator->name, SRV6_LOCNAME_SIZE)) {
			return locator;
		}
	}
	return NULL;
}

/*
 * function
 */

void static_srv6_function_add(struct srv6_function *function, struct srv6_locator *locator)
{
	listnode_add(locator->functions, function);
	strcpy(function->locator_name, locator->name);
	zsend_static_srv6_function_add(function);
}

void static_srv6_function_delete(struct srv6_function *function, struct srv6_locator *locator)
{
	zsend_static_srv6_function_delete(function);
}

struct srv6_function *static_srv6_function_lookup(const struct srv6_locator *locator, const struct prefix_ipv6 *prefix)
{
	struct srv6_function *function;
	struct listnode *node;
	for (ALL_LIST_ELEMENTS_RO(locator->functions, node, function)) {
		if (!prefix_cmp(prefix, &function->prefix)) {
			return function;
		}
	}
	return NULL;
}

struct srv6_function *static_srv6_function_find_by_request_key(
		const struct srv6_locator *locator, const uint32_t request_key)
{
	struct srv6_function *function;
	struct listnode *node;
	for (ALL_LIST_ELEMENTS_RO(locator->functions, node, function)) {
		if (request_key == function->request_key) {
			return function;
		}
	}
	return NULL;
}

/*
 * misc
 */

struct list *static_srv6_locators(void)
{
	return srv6_locators;
}

int static_srv6_config(struct vty *vty)
{
	struct listnode *lnode, *fnode;
	struct srv6_locator *locator;
	struct srv6_function *function;
	char str[256];
	for (ALL_LIST_ELEMENTS_RO((struct list *)srv6_locators, lnode, locator)) {
		for (ALL_LIST_ELEMENTS_RO((struct list *)locator->functions, fnode, function)) {
			inet_ntop(AF_INET6, &function->prefix.prefix, str, sizeof(str));
			vty_out(vty, " %s %s\n", locator->name, str);
		}
	}
	return 0;
}

void static_srv6_init(void)
{
	srv6_locators = list_new();
}
