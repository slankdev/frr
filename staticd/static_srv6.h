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

#include "lib/srv6.h"
#include "lib/prefix.h"

struct static_srv6_locator {
	char name[SRV6_LOCNAME_SIZE];
	struct list *chunks;
};

struct static_srv6_function {
	struct prefix_ipv6 sid;
	char locator[SRV6_LOCNAME_SIZE];
	int32_t allocate_index;
	bool allocated;

	enum seg6local_action_t action;
	struct seg6local_context ctx;
};

void static_srv6_init(void);

struct static_srv6_locator *static_srv6_locator_lookup(const char *name);
struct static_srv6_locator *static_srv6_locator_alloc(const char *name);
void static_srv6_locator_delete(struct static_srv6_locator *loc);
struct static_srv6_locator *static_srv6_locator_get(const char *name);

struct static_srv6_function *static_srv6_function_alloc(
		const char *locator_name,
		int32_t allocate_index,
		enum seg6local_action_t action,
		struct seg6local_context *ctx);
void static_srv6_function_delete(struct static_srv6_function *fun);
struct static_srv6_function *static_srv6_function_lookup(
		const char *locator_name,
		int32_t allocate_index,
		enum seg6local_action_t action,
		struct seg6local_context *ctx);
struct static_srv6_function *static_srv6_function_get(
		const char *locator_name,
		int32_t allocate_index,
		enum seg6local_action_t action,
		struct seg6local_context *ctx);
