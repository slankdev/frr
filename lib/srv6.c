/*
 * SRv6 definitions
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

#include "zebra.h"

#include "srv6.h"
#include "log.h"

DEFINE_QOBJ_TYPE(srv6_locator)
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR, "SRV6 locator")
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR_CHUNK, "SRV6 locator chunk")
DEFINE_MTYPE_STATIC(LIB, SRV6_FUNCTION, "SRV6 function")

const char *seg6local_action2str(uint32_t action)
{
	switch (action) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		return "End";
	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
		return "End.X";
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
		return "End.T";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
		return "End.DX2";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		return "End.DX6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		return "End.DX4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
		return "End.DT6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		return "End.DT4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
		return "End.B6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
		return "End.B6.Encap";
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
		return "End.BM";
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
		return "End.S";
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
		return "End.AS";
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
		return "End.AM";
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
		return "unspec";
	default:
		return "unknown";
	}
}

int snprintf_seg6_segs(char *str,
		size_t size, const struct seg6_segs *segs)
{
	str[0] = '\0';
	for (size_t i = 0; i < segs->num_segs; i++) {
		char addr[INET6_ADDRSTRLEN];
		bool not_last = (i + 1) < segs->num_segs;

		inet_ntop(AF_INET6, &segs->segs[i], addr, sizeof(addr));
		strlcat(str, addr, size);
		strlcat(str, not_last ? "," : "", size);
	}
	return strlen(str);
}

const char *seg6local_context2str(char *str, size_t size,
				  const struct seg6local_context *ctx,
				  uint32_t action)
{
	char b0[128];

	switch (action) {

	case ZEBRA_SEG6_LOCAL_ACTION_END:
		snprintf(str, size, "USP");
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		inet_ntop(AF_INET6, &ctx->nh6, b0, 128);
		snprintf(str, size, "nh6 %s", b0);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		inet_ntop(AF_INET, &ctx->nh4, b0, 128);
		snprintf(str, size, "nh4 %s", b0);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		snprintf(str, size, "table %u", ctx->table);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
	default:
		snprintf(str, size, "unknown(%s)", __func__);
		return str;
	}
}

struct srv6_locator *srv6_locator_alloc(const char *name)
{
	struct srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_SRV6_LOCATOR, sizeof(struct srv6_locator));
	strlcpy(locator->name, name, sizeof(locator->name));
	locator->functions = list_new();
	locator->chunks = list_new();
	QOBJ_REG(locator, srv6_locator);
	return locator;
}

struct srv6_locator_chunk *srv6_locator_chunk_alloc(void)
{
	struct srv6_locator_chunk *chunk = NULL;

	chunk = XCALLOC(MTYPE_SRV6_LOCATOR_CHUNK, sizeof(struct srv6_locator_chunk));
	return chunk;
}

void srv6_locator_free(struct srv6_locator *locator)
{
	list_delete(&locator->functions);
	XFREE(MTYPE_SRV6_LOCATOR, locator);
}

void srv6_locator_chunk_free(struct srv6_locator_chunk *chunk)
{
	XFREE(MTYPE_SRV6_LOCATOR_CHUNK, chunk);
}

struct srv6_function *srv6_function_alloc(const struct prefix_ipv6 *prefix)
{
	struct srv6_function *function = NULL;

	function = XCALLOC(MTYPE_SRV6_FUNCTION, sizeof(struct srv6_function));
	function->prefix = *prefix;
	return function;
}

void srv6_function_init(struct srv6_function *function,
			const char *locator_name,
			const struct prefix_ipv6 *prefix)
{
	function->prefix.family = AF_INET6;
	strlcpy(function->locator_name, locator_name,
		sizeof(function->locator_name));
	if (prefix)
		function->prefix = *prefix;
}

void srv6_function_free(struct srv6_function *function)
{
	XFREE(MTYPE_SRV6_FUNCTION, function);
}
