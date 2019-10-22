/* SRv6-VPN
 * Copyright (C) 2019 Hiroki Shirokura <slank.dev@gmail.com>
 *
 * This file is part of GxNU Zebra.
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
#ifndef _QUAGGA_BGP_SRV6VPN_H
#define _QUAGGA_BGP_SRV6VPN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_zebra.h"


extern void bgp_srv6vpn_init(void);
extern int bgp_nlri_parse_srv6vpn(struct peer *, struct attr *, struct bgp_nlri *);
extern int bgp_show_srv6_vpn(struct vty *vty, afi_t afi,
		struct prefix_rd *prd, enum bgp_show_type type,
		void *output_arg, int tags, bool use_json);

extern void srv6vpn_leak_from_vrf_update(struct bgp *bgp_vpn,
		struct bgp *bgp_vrf, struct bgp_path_info *path_vrf);
extern void srv6vpn_leak_from_vrf_withdraw(struct bgp *bgp_vpn,
		struct bgp *bgp_vrf, struct bgp_path_info *path_vrf);
extern void srv6vpn_leak_from_vrf_withdraw_all(struct bgp *bgp_vpn,
		struct bgp *bgp_vrf, afi_t afi);
extern void srv6vpn_leak_from_vrf_update_all(
		struct bgp *bgp_vpn, struct bgp *bgp_vrf, afi_t afi);
extern void srv6vpn_leak_to_vrf_withdraw_all(
		struct bgp *bgp_vrf, afi_t afi);
extern void srv6vpn_leak_to_vrf_update_all(
		struct bgp *bgp_vrf, struct bgp *bgp_vpn, afi_t afi);
extern void srv6vpn_leak_to_vrf_update(
		struct bgp *bgp_vpn, struct bgp_path_info *path_vpn);
extern void srv6vpn_leak_to_vrf_withdraw(
		struct bgp *bgp_vpn, struct bgp_path_info *path_vpn);

extern int vpn_leak_sid_callback(
		struct in6_addr *sid,
		void *lblid, bool alloc);

extern void srv6vpn_leak_zebra_vrf_sid_update(struct bgp *bgp, afi_t afi);
extern void srv6vpn_leak_zebra_vrf_sid_withdraw(struct bgp *bgp, afi_t afi);

extern int srv6vpn_leak_to_vpn_active(
		struct bgp *bgp_vrf, afi_t afi, const char **pmsg);
extern int srv6vpn_leak_from_vpn_active(
		struct bgp *bgp_vrf, afi_t afi, const char **pmsg);
extern void srv6vpn_leak_prechange(
		srv6vpn_policy_direction_t direction, afi_t afi,
		struct bgp *bgp_vpn, struct bgp *bgp_vrf);
extern void srv6vpn_leak_postchange(
		srv6vpn_policy_direction_t direction, afi_t afi,
		struct bgp *bgp_vpn, struct bgp *bgp_vrf);
extern bool is_route_injectable_into_srv6vpn(struct bgp_path_info *pi);
extern bool is_pi_family_srv6vpn(struct bgp_path_info *pi);

extern void srv6vpn_policy_routemap_event(const char *rmap_name);
extern vrf_id_t get_first_srv6vrf_for_redirect_with_rt(struct ecommunity *eckey);
extern void srv6vpn_leak_postchange_all(void);
extern void srv6vpn_handle_router_id_update(struct bgp *bgp, bool withdraw, bool is_config);
extern int srv6bgp_vpn_leak_unimport(struct bgp *from_bgp, struct vty *vty);
extern void bgp_srv6vpn_leak_export(struct bgp *from_bgp);

#endif /* _QUAGGA_BGP_SRV6VPN_H */
