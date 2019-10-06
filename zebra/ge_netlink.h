/* Header file exported by ge_netlink.c to zebra.
 * Copyright (C) 2019, Hiroki Shirokura
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
#ifndef _ZEBRA_GE_NETLINK_H
#define _ZEBRA_GE_NETLINK_H

#include <netinet/in.h>
#include <linux/seg6_genl.h>
#include <linux/genetlink.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GENL_REQUEST(_req, _bufsiz, _family, _hdrsiz, _ver, _cmd, _flags) \
struct {								\
	struct nlmsghdr		n;					\
	struct genlmsghdr	g;					\
	char			buf[NLMSG_ALIGN(_hdrsiz) + (_bufsiz)];	\
} _req = {								\
	.n = {								\
		.nlmsg_type = (_family),				\
		.nlmsg_flags = (_flags),				\
		.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + (_hdrsiz)),	\
	},								\
	.g = {								\
		.cmd = (_cmd),						\
		.version = (_ver),					\
	},								\
}


extern void ge_netlink_init(void);
extern void ge_netlink_sr_tunsrc_read(void);
extern void ge_netlink_sr_tunsrc_change(struct in6_addr *src);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_GE_NETLINK_H */
