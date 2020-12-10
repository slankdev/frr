/*
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

#include "vrf.h"
#include "nexthop.h"
#include "table.h"
#include "srcdest_table.h"

#include "static_srv6.h"
#include "static_memory.h"
#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_vty.h"

struct list *srv6_locators;
struct list *srv6_functions;

struct static_srv6_locator *static_srv6_locator_lookup(const char *name)
{
	struct listnode *node;
	struct static_srv6_locator *loc;
	struct static_srv6_locator *loc_found = NULL;

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node, loc)) {
		if (strcmp(loc->name, name) != 0)
			continue;
		loc_found = loc;
		break;
	}

	return loc_found;
}

struct static_srv6_locator *static_srv6_locator_alloc(const char *name)
{
	struct static_srv6_locator *loc;

	loc = XCALLOC(MTYPE_TMP, sizeof(struct static_srv6_locator));
	loc->chunks = list_new();
	snprintf(loc->name, SRV6_LOCNAME_SIZE, "%s", name);
	return loc;
}

void static_srv6_locator_delete(struct static_srv6_locator *loc)
{
	list_delete_all_node(loc->chunks);
	XFREE(MTYPE_TMP, loc);
}

struct static_srv6_locator *static_srv6_locator_get(const char *name)
{
	struct static_srv6_locator *loc;
	loc = static_srv6_locator_lookup(name);
	if (!loc) {
		loc = static_srv6_locator_alloc(name);
		listnode_add(srv6_locators, loc);
	}
	return loc;
}

/*
 * allocate_index: -1(auto), else(specify index)
 */
struct static_srv6_function *static_srv6_function_alloc(
		const char *locator_name,
		int32_t allocate_index,
		enum seg6local_action_t action,
		struct seg6local_context *ctx)
{
	struct static_srv6_function *fun;

	fun = XCALLOC(MTYPE_TMP, sizeof(struct static_srv6_function));
	fun->allocate_index = allocate_index;
	fun->action = action;
	fun->ctx = *ctx;
	snprintf(fun->locator, SRV6_LOCNAME_SIZE, "%s", locator_name);

	return fun;
}

void static_srv6_function_delete(struct static_srv6_function *fun)
{
	XFREE(MTYPE_TMP, fun);
}

struct static_srv6_function *static_srv6_function_lookup(
		const char *locator_name,
		int32_t allocate_index,
		enum seg6local_action_t action,
		struct seg6local_context *ctx)
{
	struct listnode *node;
	struct static_srv6_function *fun;
	struct static_srv6_function *fun_found = NULL;

	for (ALL_LIST_ELEMENTS_RO(srv6_functions, node, fun)) {
		if (strcmp(fun->locator, locator_name) != 0 ||
		    fun->allocate_index != allocate_index ||
		    fun->action != action ||
		    memcmp(&fun->ctx, ctx, sizeof(fun->ctx) != 0))
			continue;
		fun_found = fun;
		break;
	}

	return fun_found;
}

struct static_srv6_function *static_srv6_function_get(
		const char *locator_name,
		int32_t allocate_index,
		enum seg6local_action_t action,
		struct seg6local_context *ctx)
{
	struct static_srv6_function *fun;
	fun = static_srv6_function_lookup(locator_name, allocate_index,
					  action, ctx);
	if (!fun) {
		fun = static_srv6_function_alloc(locator_name, allocate_index,
						 action, ctx);
		listnode_add(srv6_functions, fun);
	}
	return fun;
}

void static_srv6_init(void)
{
	srv6_locators = list_new();
	srv6_functions = list_new();
	return;
}
