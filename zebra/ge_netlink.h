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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <linux/genetlink.h>

#include <zebra/zebra_ns.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void ge_netlink_init(void);
extern void ge_netlink_sr_tunsrc_read(void);
extern int ge_netlink_resolve_family(int fd, const char* family_name);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_GE_NETLINK_H */
