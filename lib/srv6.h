/*
 * SEG6 definitions
 * Copyright 2019 Hiroki Shirokura
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#ifndef _FRR_SRV6_H
#define _FRR_SRV6_H

#include <zebra.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/seg6_iptunnel.h>
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>

#define SRV6_MAX_SIDS 16

#ifdef __cplusplus
extern "C" {
#endif

enum seg6_mode_t {
	INLINE,
	ENCAP,
	L2ENCAP,
};

struct seg6_segs {
	size_t num_segs;
	struct in6_addr segs[256];
};

struct seg6local_context {
	struct in_addr nh4;
	struct in6_addr nh6;
	uint32_t table;
};

inline static const char*
seg6_mode2str(enum seg6_mode_t mode)
{
	switch (mode) {
		case INLINE : return "INLINE";
		case ENCAP  : return "ENCAP";
		case L2ENCAP: return "L2ENCAP";
		default:
			abort();
	}
}

inline static const char*
seg6local_action2str(uint32_t action)
{
	switch (action) {
		case SEG6_LOCAL_ACTION_END: return "End";
		case SEG6_LOCAL_ACTION_END_X: return "End.X";
		case SEG6_LOCAL_ACTION_END_T: return "End.T";
		case SEG6_LOCAL_ACTION_END_DX2: return "End.DX2";
		case SEG6_LOCAL_ACTION_END_DX6: return "End.DX6";
		case SEG6_LOCAL_ACTION_END_DX4: return "End.DX4";
		case SEG6_LOCAL_ACTION_END_DT6: return "End.DT6";
		case SEG6_LOCAL_ACTION_END_DT4: return "End.DT4";
		case SEG6_LOCAL_ACTION_END_B6: return "End.B6";
		case SEG6_LOCAL_ACTION_END_B6_ENCAP: return "End.B6.Encap";
		case SEG6_LOCAL_ACTION_END_BM: return "End.BM";
		case SEG6_LOCAL_ACTION_END_S: return "End.S";
		case SEG6_LOCAL_ACTION_END_AS: return "End.AS";
		case SEG6_LOCAL_ACTION_END_AM: return "End.AM";

		case SEG6_LOCAL_ACTION_UNSPEC:
		default:
			printf("ABORT...\n");
			abort();
	}
}

extern const char*
seg6local_context2str(char *str, size_t size,
		struct seg6local_context *ctx, uint32_t action);

extern int snprintf_seg6_segs(char *str,
		size_t size, const struct seg6_segs *segs);

static inline bool sid_same(
		const struct in6_addr *a,
		const struct in6_addr *b)
{ return memcmp(a, b, sizeof(struct in6_addr)) == 0; }

static inline bool sid_diff(
		const struct in6_addr *a,
		const struct in6_addr *b)
{ return !sid_same(a, b); }

static inline bool sid_zero(
		const struct in6_addr *a)
{
	uint8_t zero[16] = {0};
	return sid_same(a, (const struct in6_addr*)zero);
}

static inline void* sid_copy(struct in6_addr *dst,
		const struct in6_addr *src)
{ return memcpy(dst, src, sizeof(struct in6_addr)); }

static inline const char* sid2str(
		const struct in6_addr *sid, char *str, size_t size)
{ return inet_ntop(AF_INET6, sid, str, size); }

static inline struct ipv6_sr_hdr *parse_srh(bool encap,
    size_t num_segs, const struct in6_addr *segs)
{
  const size_t srhlen = 8 + sizeof(struct in6_addr)*(encap ? num_segs+1 : num_segs);

  struct ipv6_sr_hdr *srh = malloc(srhlen);
  memset(srh, 0, srhlen);
  srh->hdrlen = (srhlen >> 3) - 1;
  srh->type = 4;
  srh->segments_left = encap ? num_segs : num_segs - 1;
  srh->first_segment = encap ? num_segs : num_segs - 1;

  size_t srh_idx = encap ? 1 : 0;
  for (ssize_t i=num_segs-1; i>=0; i--)
    memcpy(&srh->segments[srh_idx + i], &segs[num_segs - 1 - i], sizeof(struct in6_addr));
  return srh;
}

#ifdef __cplusplus
}
#endif

#endif
