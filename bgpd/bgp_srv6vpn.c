/* SRv6-VPN
 * Copyright (C) 2019 Hiroki Shirokura <slank.dev@gmail.com>
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

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "queue.h"
#include "filter.h"
#include "mpls.h"
#include "json.h"
#include "zclient.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_srv6vpn.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_vpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_evpn.h"

/*
 * Definitions and external declarations.
 */
extern struct zclient *zclient;

static void set_zebra_srv6_encap_rule(
		const struct in_addr *pref, uint32_t plen,
		uint32_t num_segs, const struct in6_addr *segs,
		uint32_t table_id)
{
	struct zapi_seg6 api;
	memset(&api, 0, sizeof(api));

	api.afi = AF_INET;
	memcpy(&api.pref4, pref, sizeof(struct in_addr));
	api.plen = plen;
	api.table_id = table_id;
	api.mode = ENCAP;
	api.num_segs = num_segs;
	for (size_t i=0; i<api.num_segs; i++)
		memcpy(&api.segs[i], &segs[i], sizeof(struct in6_addr));

	vrf_id_t vrf_id = 0; /* global vrf */
	struct stream *s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_SEG6_ADD, vrf_id);

	stream_putl(s, api.afi);
	stream_write(s, &api.pref4, sizeof(struct in_addr));
	stream_write(s, &api.pref6, sizeof(struct in6_addr));
	stream_putl(s, api.plen);
	stream_putl(s, api.table_id);
	stream_putl(s, api.mode);
	stream_putl(s, api.num_segs);
	for (size_t i=0; i<api.num_segs; i++)
		stream_write(s, &api.segs[i], sizeof(struct in6_addr));

	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

extern int srv6vpn_leak_to_vpn_active(struct bgp *bgp_vrf, afi_t afi, const char **pmsg)
{
	if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF
		&& bgp_vrf->inst_type != BGP_INSTANCE_TYPE_DEFAULT) {

		if (pmsg)
			*pmsg = "source bgp instance neither vrf nor default";
		return 0;
	}

	/* Is vrf configured to export to vpn? */
	if (!CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
			BGP_CONFIG_VRF_TO_SRV6VPN_EXPORT)
	    && !CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
			   BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
		if (pmsg)
			*pmsg = "export not set";
		return 0;
	}

	/* Is there an RT list set? */
	if (!bgp_vrf->srv6vpn_policy[afi].rtlist[BGP_SRV6VPN_POLICY_DIR_TOVPN]) {
		if (pmsg)
			*pmsg = "rtlist tovpn not defined";
		return 0;
	}

	/* Is there an RD set? */
	if (!CHECK_FLAG(bgp_vrf->srv6vpn_policy[afi].flags,
			BGP_SRV6VPN_POLICY_TOVPN_RD_SET)) {
		if (pmsg)
			*pmsg = "rd not defined";
		return 0;
	}

	/* Is a route-map specified, but not defined? */
	if (bgp_vrf->srv6vpn_policy[afi].rmap_name[BGP_SRV6VPN_POLICY_DIR_TOVPN] &&
		!bgp_vrf->srv6vpn_policy[afi].rmap[BGP_SRV6VPN_POLICY_DIR_TOVPN]) {
		if (pmsg)
			*pmsg = "route-map tovpn named but not defined";
		return 0;
	}

	/* Is there an "auto" export sid that isn't allocated yet? */
	uint8_t sid_none[16] = {0};
	if (CHECK_FLAG(bgp_vrf->srv6vpn_policy[afi].flags,
		BGP_SRV6VPN_POLICY_TOVPN_SID_AUTO) &&
		memcmp(&bgp_vrf->srv6vpn_policy[afi].tovpn_sid,
			     sid_none, sizeof(struct in6_addr)) == 0) {

		if (pmsg)
			*pmsg = "auto sid not allocated";
		return 0;
	}

	return 1;
}

extern int srv6vpn_leak_from_vpn_active(struct bgp *bgp_vrf, afi_t afi,
					   const char **pmsg)
{
	if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF
		&& bgp_vrf->inst_type != BGP_INSTANCE_TYPE_DEFAULT) {

		if (pmsg)
			*pmsg = "destination bgp instance neither vrf nor default";
		return 0;
	}

	if (bgp_vrf->vrf_id == VRF_UNKNOWN) {
		if (pmsg)
			*pmsg = "destination bgp instance vrf is VRF_UNKNOWN";
		return 0;
	}

	/* Is vrf configured to import from vpn? */
	bool b0 = !CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_SRV6VPN_TO_VRF_IMPORT);
	bool b1 = !CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_VRF_TO_VRF_IMPORT);
	if (b0 && b1) {
		if (pmsg)
			*pmsg = "import not set";
		return 0;
	}

	/* Is there an RT list set? */
	if (!bgp_vrf->srv6vpn_policy[afi].rtlist[BGP_SRV6VPN_POLICY_DIR_FROMVPN]) {
		if (pmsg)
			*pmsg = "rtlist fromvpn not defined";
		return 0;
	}

	/* Is a route-map specified, but not defined? */
	if (bgp_vrf->srv6vpn_policy[afi].rmap_name[BGP_SRV6VPN_POLICY_DIR_FROMVPN] &&
		!bgp_vrf->srv6vpn_policy[afi].rmap[BGP_SRV6VPN_POLICY_DIR_FROMVPN]) {
		if (pmsg)
			*pmsg = "route-map fromvpn named but not defined";
		return 0;
	}
	return 1;
}

static int ecom_intersect(struct ecommunity *e1, struct ecommunity *e2)
{
	int i;
	int j;

	if (!e1 || !e2)
		return 0;

	for (i = 0; i < e1->size; ++i) {
		for (j = 0; j < e2->size; ++j) {
			if (!memcmp(e1->val + (i * ECOMMUNITY_SIZE),
				    e2->val + (j * ECOMMUNITY_SIZE),
				    ECOMMUNITY_SIZE)) {

				return 1;
			}
		}
	}
	return 0;
}

void srv6vpn_leak_to_vrf_withdraw(struct bgp *bgp_vpn,	    /* from */
			      struct bgp_path_info *path_vpn) /* route */
{
	struct prefix *p;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp;
	struct listnode *mnode, *mnnode;
	struct bgp_node *bn;
	struct bgp_path_info *bpi;
	const char *debugmsg;
	char buf_prefix[PREFIX_STRLEN];

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug) {
		prefix2str(&path_vpn->net->p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: entry: p=%s, type=%d, sub_type=%d", __func__,
			   buf_prefix, path_vpn->type, path_vpn->sub_type);
	}

	if (debug)
		zlog_debug("%s: start (path_vpn=%p)", __func__, path_vpn);

	if (!path_vpn->net) {
		if (debug)
			zlog_debug(
				"%s: path_vpn->net unexpectedly NULL, no prefix, bailing",
				__func__);
		return;
	}

	p = &path_vpn->net->p;
	afi = family2afi(p->family);

	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {

		zlog_debug("%s: -begin-for----------", __func__);

		if (!srv6vpn_leak_from_vpn_active(bgp, afi, &debugmsg)) {
			if (debug)
				zlog_debug("%s: skipping: %s", __func__,
					   debugmsg);
			continue;
		}

		/* Check for intersection of route targets */
		if (!ecom_intersect(bgp->srv6vpn_policy[afi]
					    .rtlist[BGP_SRV6VPN_POLICY_DIR_FROMVPN],
				    path_vpn->attr->ecommunity)) {

			continue;
		}

		if (debug)
			zlog_debug("%s: withdrawing from vrf %s", __func__,
				   bgp->name_pretty);

		bn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, NULL);

		for (bpi = bgp_node_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (bpi->extra
			    && (struct bgp_path_info *)bpi->extra->parent
				       == path_vpn) {
				break;
			}
		}

		if (bpi) {
			if (debug)
				zlog_debug("%s: deleting bpi %p", __func__,
					   bpi);
			bgp_aggregate_decrement(bgp, p, bpi, afi, safi);
			bgp_path_info_delete(bn, bpi);
			bgp_process(bgp, bn, afi, safi);
		}
		bgp_unlock_node(bn);
	}
}

extern void srv6vpn_leak_prechange(srv6vpn_policy_direction_t direction,
				      afi_t afi, struct bgp *bgp_vpn,
				      struct bgp *bgp_vrf)
{
	/* Detect when default bgp instance is not (yet) defined by config */
	if (!bgp_vpn)
		return;

	if ((direction == BGP_SRV6VPN_POLICY_DIR_FROMVPN) &&
		srv6vpn_leak_from_vpn_active(bgp_vrf, afi, NULL)) {

		srv6vpn_leak_to_vrf_withdraw_all(bgp_vrf, afi);
	}
	if ((direction == BGP_SRV6VPN_POLICY_DIR_TOVPN) &&
		srv6vpn_leak_to_vpn_active(bgp_vrf, afi, NULL)) {

		srv6vpn_leak_from_vrf_withdraw_all(bgp_vpn, bgp_vrf, afi);
	}
}

extern void srv6vpn_leak_postchange(srv6vpn_policy_direction_t direction,
				       afi_t afi, struct bgp *bgp_vpn,
				       struct bgp *bgp_vrf)
{
	zlog_debug("%s:%d dir=%s afi=%u bgp_vpn=%s bgp_vrf=%s", __func__, __LINE__,
			srv6vpn_policy_direction2str(direction), afi,
			bgp_vpn->name, bgp_vrf->name);

	/* Detect when default bgp instance is not (yet) defined by config */
	if (!bgp_vpn)
		return;

	if (direction == BGP_SRV6VPN_POLICY_DIR_FROMVPN) {
		srv6vpn_leak_to_vrf_update_all(bgp_vrf, bgp_vpn, afi);
	}
	if (direction == BGP_SRV6VPN_POLICY_DIR_TOVPN) {

		struct in6_addr *tovpn_sid = &bgp_vrf->srv6vpn_policy[afi].tovpn_sid;
		struct in6_addr *tovpn_sid_last_sent =
			&bgp_vrf->srv6vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent;
		if (sid_diff(tovpn_sid, tovpn_sid_last_sent)) {
			srv6vpn_leak_zebra_vrf_sid_update(bgp_vrf, afi);
		}

		srv6vpn_leak_from_vrf_update_all(bgp_vpn, bgp_vrf, afi);
	}
}

/* Flag if the route is injectable into VPN. This would be either a
 * non-imported route or a non-VPN imported route.
 */
extern bool is_route_injectable_into_srv6vpn(struct bgp_path_info *pi)
{
	struct bgp_path_info *parent_pi;
	struct bgp_table *table;
	struct bgp_node *rn;

	if (pi->sub_type != BGP_ROUTE_IMPORTED ||
	    !pi->extra ||
	    !pi->extra->parent)
		return true;

	parent_pi = (struct bgp_path_info *)pi->extra->parent;
	rn = parent_pi->net;
	if (!rn)
		return true;
	table = bgp_node_table(rn);
	if (table &&
	    (table->afi == AFI_IP || table->afi == AFI_IP6) &&
	    table->safi == SAFI_SRV6_VPN)
		return false;
	return true;
}

/* Flag if the route path's family is VPN. */
extern bool is_pi_family_srv6vpn(struct bgp_path_info *pi)
{
	return (is_pi_family_matching(pi, AFI_IP, SAFI_SRV6_VPN) ||
		is_pi_family_matching(pi, AFI_IP6, SAFI_SRV6_VPN));
}

/*
 * This function informs zebra of the label this vrf sets on routes
 * leaked to VPN. Zebra should install this label in the kernel with
 * an action of "pop label and then use this vrf's IP FIB to route the PDU."
 *
 * Sending this vrf-label association is qualified by a) whether vrf->vpn
 * exporting is active ("export vpn" is enabled, vpn-policy RD and RT list
 * are set) and b) whether vpn-policy label is set.
 *
 * If any of these conditions do not hold, then we send MPLS_LABEL_NONE
 * for this vrf, which zebra interprets to mean "delete this vrf-label
 * association."
 */
void srv6vpn_leak_zebra_vrf_sid_update(struct bgp *bgp, afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug) {
			zlog_debug(
				"%s: vrf %s: afi %s: vrf_id not set, "
				"can't set zebra vrf label",
				__func__, bgp->name_pretty, afi2str(afi));
		}
		return;
	}

	struct in6_addr sid;
	memset(&sid, 0, sizeof(struct in6_addr));
	if (srv6vpn_leak_to_vpn_active(bgp, afi, NULL)) {
		memcpy(&sid, &bgp->srv6vpn_policy[afi].tovpn_sid, sizeof(struct in6_addr));
	}

	if (debug) {
		char str[128];
		inet_ntop(AF_INET6, &bgp->srv6vpn_policy[afi].tovpn_sid, str, sizeof(str));
		zlog_debug("%s: vrf %s: afi %s: setting sid %s for vrf id %d",
			   __func__, bgp->name_pretty, afi2str(afi), str,
			   bgp->vrf_id);
	}

	if (sid_zero(&sid))
		return;

	struct vrf *vrf = bgp_vrf_lookup_by_instance_type(bgp);
	zclient_send_vrf_seg6local_dx4(zclient, afi, &sid, vrf->data.l.table_id);
	memcpy(&bgp->srv6vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent, &sid, sizeof(struct in6_addr));
}

/*
 * If zebra tells us vrf has become unconfigured, tell zebra not to
 * use this label to forward to the vrf anymore
 */
void srv6vpn_leak_zebra_vrf_sid_withdraw(struct bgp *bgp, afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug) {
			zlog_debug(
				"%s: vrf_id not set, can't delete zebra vrf label",
				__func__);
		}
		return;
	}

	struct in6_addr sid = {0};
	if (debug) {
		zlog_debug("%s: deleting sid for vrf %s (id=%d)", __func__,
			   bgp->name_pretty, bgp->vrf_id);
	}

	struct vrf *vrf = bgp_vrf_lookup_by_instance_type(bgp);
	zclient_send_vrf_seg6local_dx4(zclient, afi, &sid, vrf->data.l.table_id);
	memcpy(&bgp->srv6vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent, &sid, 16);
}

static bool sids_same(struct bgp_path_info *bpi, struct in6_addr *sid,
			uint32_t n)
{
	if (!bpi->extra) {
		if (!n)
			return true;
		else
			return false;
	}

	if (n != bpi->extra->num_sids)
		return false;

	for (uint32_t i = 0; i < n; ++i) {
		if (sid_diff(&sid[i], &bpi->extra->sid[i]))
			return false;
	}
	return true;
}


/*
 * make encoded route SIDs match specified encoded sid set
 */
static void setsids(struct bgp_path_info *bpi,
		      struct in6_addr *sid, /* array of sids */
		      uint32_t num_sids)
{
	if (num_sids)
		assert(sid);
	assert(num_sids <= BGP_MAX_SIDS);

	if (!num_sids) {
		if (bpi->extra)
			bpi->extra->num_sids = 0;
		return;
	}

	struct bgp_path_info_extra *extra = bgp_path_info_extra_get(bpi);
	for (size_t i=0; i<num_sids; i++) {
		memcpy(&extra->sid[i], &sid[i], 16);
	}
	extra->num_sids = num_sids;
}


/*
 * returns pointer to new bgp_path_info upon success
 */
static struct bgp_path_info *
leak_update(struct bgp *bgp, /* destination bgp instance */
	    struct bgp_node *bn, struct attr *new_attr, /* already interned */
	    afi_t afi, safi_t safi, struct bgp_path_info *source_bpi,
	    mpls_label_t *label, uint32_t num_labels, void *parent,
	    struct bgp *bgp_orig, struct prefix *nexthop_orig,
	    int nexthop_self_flag, int debug)
{
	struct prefix *p = &bn->p;
	struct bgp_path_info *bpi;
	struct bgp_path_info *bpi_ultimate;
	struct bgp_path_info *new;
	char buf_prefix[PREFIX_STRLEN];

	uint32_t num_sids = 0;
	struct in6_addr sids[1];
	memset(sids, 0, sizeof(sids));
	if (!sid_zero(&new_attr->sid)) {
		num_sids = 1;
		memcpy(&sids[0], &new_attr->sid, 16);
	}

	if (debug) {
		prefix2str(&bn->p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: entry: leak-to=%s, p=%s, type=%d, sub_type=%d",
			   __func__, bgp->name_pretty, buf_prefix,
			   source_bpi->type, source_bpi->sub_type);
	}

	/*
	 * Routes that are redistributed into BGP from zebra do not get
	 * nexthop tracking. However, if those routes are subsequently
	 * imported to other RIBs within BGP, the leaked routes do not
	 * carry the original BGP_ROUTE_REDISTRIBUTE sub_type. Therefore,
	 * in order to determine if the route we are currently leaking
	 * should have nexthop tracking, we must find the ultimate
	 * parent so we can check its sub_type.
	 *
	 * As of now, source_bpi may at most be a second-generation route
	 * (only one hop back to ultimate parent for vrf-vpn-vrf scheme).
	 * Using a loop here supports more complex intra-bgp import-export
	 * schemes that could be implemented in the future.
	 *
	 */
	for (bpi_ultimate = source_bpi;
	     bpi_ultimate->extra && bpi_ultimate->extra->parent;
	     bpi_ultimate = bpi_ultimate->extra->parent)
		;

	/*
	 * match parent
	 */
	for (bpi = bgp_node_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->parent == parent)
			break;
	}

	if (bpi) {
		assert(num_labels == 0);
		bool sidssame = sids_same(bpi, sids, num_sids);

		if (attrhash_cmp(bpi->attr, new_attr) && sidssame
		    && !CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED)) {

			bgp_attr_unintern(&new_attr);
			if (debug)
				zlog_debug(
					"%s: ->%s: %s: Found route, no change",
					__func__, bgp->name_pretty,
					buf_prefix);
			return NULL;
		}

		/* attr is changed */
		bgp_path_info_set_flag(bn, bpi, BGP_PATH_ATTR_CHANGED);

		/* Rewrite BGP route information. */
		if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(bn, bpi);
		else
			bgp_aggregate_decrement(bgp, p, bpi, afi, safi);
		bgp_attr_unintern(&bpi->attr);
		bpi->attr = new_attr;
		bpi->uptime = bgp_clock();

		/*
		 * rewrite SRv6 Encap Rule
		 */
		if (!sidssame)
		     setsids(bpi, sids, num_sids);

		if (nexthop_self_flag)
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_ANNC_NH_SELF);

		struct bgp *bgp_nexthop = bgp;
		int nh_valid;

		if (bpi->extra && bpi->extra->bgp_orig)
			bgp_nexthop = bpi->extra->bgp_orig;

		/*
		 * No nexthop tracking for redistributed routes or for
		 * EVPN-imported routes that get leaked.
		 */
		if (bpi_ultimate->sub_type == BGP_ROUTE_REDISTRIBUTE ||
		    is_pi_family_evpn(bpi_ultimate))
			nh_valid = 1;
		else
			/*
			 * TBD do we need to do anything about the
			 * 'connected' parameter?
			 */
			nh_valid = bgp_find_or_add_nexthop(bgp, bgp_nexthop,
							   afi, bpi, NULL, 0);

		if (debug)
			zlog_debug("%s: nexthop is %svalid (in vrf %s)",
				__func__, (nh_valid ? "" : "not "),
				bgp_nexthop->name_pretty);

		if (nh_valid)
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_VALID);

		/* Process change. */
		bgp_aggregate_increment(bgp, p, bpi, afi, safi);
		bgp_process(bgp, bn, afi, safi);
		bgp_unlock_node(bn);

		if (debug)
			zlog_debug("%s: ->%s: %s Found route, changed attr",
				   __func__, bgp->name_pretty, buf_prefix);

		return bpi;
	}

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_IMPORTED, 0,
		bgp->peer_self, new_attr, bn);

	if (nexthop_self_flag)
		bgp_path_info_set_flag(bn, new, BGP_PATH_ANNC_NH_SELF);

	bgp_path_info_extra_get(new);

	if (num_sids)
		setsids(new, sids, num_sids);

	new->extra->parent = bgp_path_info_lock(parent);
	bgp_lock_node((struct bgp_node *)((struct bgp_path_info *)parent)->net);
	if (bgp_orig)
		new->extra->bgp_orig = bgp_lock(bgp_orig);
	if (nexthop_orig)
		new->extra->nexthop_orig = *nexthop_orig;

	/*
	 * nexthop tracking for unicast routes
	 */
	struct bgp *bgp_nexthop = bgp;
	int nh_valid;

	if (new->extra->bgp_orig)
		bgp_nexthop = new->extra->bgp_orig;

	/*
	 * No nexthop tracking for redistributed routes because
	 * their originating protocols will do the tracking and
	 * withdraw those routes if the nexthops become unreachable
	 * This also holds good for EVPN-imported routes that get
	 * leaked.
	 */
	if (bpi_ultimate->sub_type == BGP_ROUTE_REDISTRIBUTE ||
	    is_pi_family_evpn(bpi_ultimate))
		nh_valid = 1;
	else
		/*
		 * TBD do we need to do anything about the
		 * 'connected' parameter?
		 */
		nh_valid = bgp_find_or_add_nexthop(bgp, bgp_nexthop,
						afi, new, NULL, 0);

	nh_valid = 1; // XXX: TODO(slankdev):

	if (debug)
		zlog_debug("%s: nexthop is %svalid (in vrf %s)",
			__func__, (nh_valid ? "" : "not "),
			bgp_nexthop->name_pretty);
	if (nh_valid)
		bgp_path_info_set_flag(bn, new, BGP_PATH_VALID);

	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {

		char str0[128];
		inet_ntop(AF_INET6, &new_attr->sid, str0, sizeof(str0));
		if (sid_zero(&new_attr->sid)) {
			zlog_warn("%s:%d:%s WARNING: empty SID",
					__FILE__, __LINE__, __func__);
		}

		const uint32_t num_segs = 1;
		struct in6_addr segs[1];
		memcpy(&segs[0], &new_attr->sid, 16);

		struct vrf *vrf = vrf_lookup_by_id(bgp->vrf_id);
		uint32_t table_id = vrf->data.l.table_id;
		assert(p->family == AF_INET);
		set_zebra_srv6_encap_rule(&p->u.prefix4,
				p->prefixlen, num_segs, segs, table_id);

		if (debug) {
			size_t len = 0;
			char str[128], d0[128], segs_str[128], ss[128];
			inet_ntop(AF_INET, &p->u.prefix4, d0, sizeof(d0));
			for (uint32_t i=0; i<num_segs; i++) {
				inet_ntop(AF_INET6, &segs[i], ss, sizeof(ss));
				snprintf(&segs_str[len], sizeof(segs_str)-len, "%s%s", ss, i+1<num_segs?",":"");
				len = strlen(segs_str);
			}
			snprintf(str, sizeof(str), "%s/%u [%s]", d0, p->prefixlen, segs_str);
			zlog_debug("%s: Added new SRv6-Encap route %s on l3mdev table %u",
					__func__, str, table_id);
		}
	}

	bgp_aggregate_increment(bgp, p, new, afi, safi);
	bgp_path_info_add(bn, new);

	bgp_unlock_node(bn);
	bgp_process(bgp, bn, afi, safi);

	if (debug)
		zlog_debug("%s: ->%s: %s: Added new route", __func__,
			   bgp->name_pretty, buf_prefix);

	return new;
}

static void
srv6vpn_leak_to_vrf_update_onevrf(struct bgp *bgp_vrf,	    /* to */
			      struct bgp *bgp_vpn,	    /* from */
			      struct bgp_path_info *path_vpn) /* route */
{
	struct prefix *p = &path_vpn->net->p;
	afi_t afi = family2afi(p->family);

	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	struct bgp_node *bn;
	safi_t safi = SAFI_UNICAST;
	const char *debugmsg;
	struct prefix nexthop_orig;
	int nexthop_self_flag = 1;
	struct bgp *src_vrf;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (!srv6vpn_leak_from_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	/* Check for intersection of route targets */
	if (!ecom_intersect(
		    bgp_vrf->srv6vpn_policy[afi].rtlist[BGP_SRV6VPN_POLICY_DIR_FROMVPN],
		    path_vpn->attr->ecommunity)) {

		return;
	}

	if (debug) {
		char buf_prefix[PREFIX_STRLEN];

		prefix2str(p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: updating %s to vrf %s", __func__,
				buf_prefix, bgp_vrf->name_pretty);
	}

	bgp_attr_dup(&static_attr, path_vpn->attr); /* shallow copy */

	/*
	 * Nexthop: stash and clear
	 *
	 * Nexthop is valid in context of VPN core, but not in destination vrf.
	 * Stash it for later label resolution by vrf ingress path and then
	 * overwrite with 0, i.e., "me", for the sake of vrf advertisement.
	 */
	uint8_t nhfamily = NEXTHOP_FAMILY(path_vpn->attr->mp_nexthop_len);

	memset(&nexthop_orig, 0, sizeof(nexthop_orig));
	nexthop_orig.family = nhfamily;

	switch (nhfamily) {
	case AF_INET:
		/* save */
		nexthop_orig.u.prefix4 = path_vpn->attr->mp_nexthop_global_in;
		nexthop_orig.prefixlen = 32;

		if (CHECK_FLAG(bgp_vrf->af_flags[afi][safi],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			static_attr.nexthop.s_addr = nexthop_orig.u.prefix4.s_addr;
			static_attr.mp_nexthop_global_in = path_vpn->attr->mp_nexthop_global_in;
			static_attr.mp_nexthop_len = path_vpn->attr->mp_nexthop_len;
		}
		static_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		break;
	case AF_INET6:
		/* save */
		nexthop_orig.u.prefix6 = path_vpn->attr->mp_nexthop_global;
		nexthop_orig.prefixlen = 128;

		if (CHECK_FLAG(bgp_vrf->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			static_attr.mp_nexthop_global = nexthop_orig.u.prefix6;
		}
		break;
	}

	/*
	 * route map handling
	 */
	if (bgp_vrf->srv6vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN]) {
		struct bgp_path_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = bgp_vrf->peer_self;
		info.attr = &static_attr;
		info.extra = path_vpn->extra; /* Used for source-vrf filter */
		ret = route_map_apply(
				bgp_vrf->srv6vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN],
				p, RMAP_BGP, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug(
					"%s: vrf %s vpn-policy route map \"%s\" says DENY, returning",
					__func__, bgp_vrf->name_pretty,
					bgp_vrf->srv6vpn_policy[afi]
						.rmap[BGP_VPN_POLICY_DIR_FROMVPN]
						->name);
			return;
		}
		/*
		 * if route-map changed nexthop, don't nexthop-self on output
		 */
		if (!CHECK_FLAG(static_attr.rmap_change_flags,
						BATTR_RMAP_NEXTHOP_UNCHANGED))
			nexthop_self_flag = 0;
	}

	new_attr = bgp_attr_intern(&static_attr);
	bgp_attr_flush(&static_attr);

	bn = bgp_afi_node_get(bgp_vrf->rib[afi][safi], afi, safi, p, NULL);

	/*
	 * ensure labels are copied
	 *
	 * However, there is a special case: if the route originated in
	 * another local VRF (as opposed to arriving via VPN), then the
	 * nexthop is reached by hairpinning through this router (me)
	 * using IP forwarding only (no LSP). Therefore, the route
	 * imported to the VRF should not have labels attached. Note
	 * that nexthop tracking is also involved: eliminating the
	 * labels for these routes enables the non-labeled nexthops
	 * from the originating VRF to be considered valid for this route.
	 */
	// TODO(slankdev):
	mpls_label_t *pLabels = NULL;
	uint32_t num_labels = 0;
	/* int origin_local = 0; */
	/* struct bgp_path_info *bpi_ultimate = NULL; */
	// if (!CHECK_FLAG(bgp_vrf->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
	// 	/* work back to original route */
	// 	for (bpi_ultimate = path_vpn;
	// 	     bpi_ultimate->extra && bpi_ultimate->extra->parent;
	// 	     bpi_ultimate = bpi_ultimate->extra->parent)
	// 		;

	// 	/*
	// 	 * if original route was unicast,
	// 	 * then it did not arrive over vpn
	// 	 */
	// 	if (bpi_ultimate->net) {
	// 		struct bgp_table *table;

	// 		table = bgp_node_table(bpi_ultimate->net);
	// 		if (table && (table->safi == SAFI_UNICAST))
	// 			origin_local = 1;
	// 	}

	// 	/* copy labels */
	// 	if (!origin_local && path_vpn->extra
	// 	    && path_vpn->extra->num_labels) {
	// 		num_labels = path_vpn->extra->num_labels;
	// 		if (num_labels > BGP_MAX_LABELS)
	// 			num_labels = BGP_MAX_LABELS;
	// 		pLabels = path_vpn->extra->label;
	// 	}
	// }

	// if (debug) {
	// 	char buf_prefix[PREFIX_STRLEN];
	// 	prefix2str(p, buf_prefix, sizeof(buf_prefix));
	// 	zlog_debug("%s: pfx %s: num_labels %d", __func__, buf_prefix,
	// 		   num_labels);
	// }

	/*
	 * For VRF-2-VRF route-leaking,
	 * the source will be the originating VRF.
	 */
	if (path_vpn->extra && path_vpn->extra->bgp_orig)
		src_vrf = path_vpn->extra->bgp_orig;
	else
		src_vrf = bgp_vpn;

	leak_update(bgp_vrf, bn, new_attr, afi, safi, path_vpn, pLabels,
		    num_labels, path_vpn, /* parent */
		    src_vrf, &nexthop_orig, nexthop_self_flag, debug);
}

void srv6vpn_leak_to_vrf_update(struct bgp *bgp_vpn,	    /* from */
			    struct bgp_path_info *path_vpn) /* route */
{
	struct listnode *mnode, *mnnode;
	struct bgp *bgp;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: start (path_vpn=%p)", __func__, path_vpn);

	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {

		if (!path_vpn->extra || path_vpn->extra->bgp_orig != bgp) { /* no loop */
			srv6vpn_leak_to_vrf_update_onevrf(bgp, bgp_vpn, path_vpn);
		}
	}
}

/* cf vnc_import_bgp_add_route_mode_nvegroup() and add_vnc_route() */
void srv6vpn_leak_from_vrf_update(struct bgp *bgp_vpn,	    /* to */
			      struct bgp *bgp_vrf,	    /* from */
			      struct bgp_path_info *path_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct prefix *p = &path_vrf->net->p;
	afi_t afi = family2afi(p->family);
	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	struct bgp_node *bn;
	const char *debugmsg;

	if (debug)
		zlog_debug("%s: from vrf %s", __func__, bgp_vrf->name_pretty);

	if (debug && path_vrf->attr->ecommunity) {
		char *s = ecommunity_ecom2str(path_vrf->attr->ecommunity,
					      ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: %s path_vrf->type=%d, EC{%s}", __func__,
			   bgp_vrf->name, path_vrf->type, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	if (!bgp_vpn)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	/* Is this route exportable into the VPN table? */
	if (!is_route_injectable_into_srv6vpn(path_vrf))
		return;

	if (!srv6vpn_leak_to_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: %s skipping: %s", __func__,
				   bgp_vrf->name, debugmsg);
		return;
	}
	zlog_debug("%s: not skipped", __func__);

	bgp_attr_dup(&static_attr, path_vrf->attr); /* shallow copy */

	/*
	 * route map handling
	 */
	if (bgp_vrf->srv6vpn_policy[afi].rmap[BGP_SRV6VPN_POLICY_DIR_TOVPN]) {
		struct bgp_path_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = bgp_vpn->peer_self;
		info.attr = &static_attr;
		ret = route_map_apply(
			bgp_vrf->srv6vpn_policy[afi].rmap[BGP_SRV6VPN_POLICY_DIR_TOVPN],
			p, RMAP_BGP, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug(
					"%s: vrf %s route map \"%s\" says DENY, returning",
					__func__, bgp_vrf->name_pretty,
					bgp_vrf->srv6vpn_policy[afi]
						.rmap[BGP_SRV6VPN_POLICY_DIR_TOVPN]
						->name);
			return;
		}
	}

	if (debug && static_attr.ecommunity) {
		char *s = ecommunity_ecom2str(static_attr.ecommunity, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		zlog_debug("%s: post route map static_attr.ecommunity{%s}", __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	/*
	 * Add the vpn-policy rt-list
	 */
	struct ecommunity *old_ecom;
	struct ecommunity *new_ecom;

	old_ecom = static_attr.ecommunity;
	if (old_ecom) {
		new_ecom = ecommunity_merge(ecommunity_dup(old_ecom),
			bgp_vrf->srv6vpn_policy[afi].rtlist[BGP_SRV6VPN_POLICY_DIR_TOVPN]);
		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	} else {
		new_ecom = ecommunity_dup(bgp_vrf->srv6vpn_policy[afi].rtlist[BGP_SRV6VPN_POLICY_DIR_TOVPN]);
	}
	static_attr.ecommunity = new_ecom;
	SET_FLAG(static_attr.flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES));

	if (debug && static_attr.ecommunity) {
		char *s = ecommunity_ecom2str(static_attr.ecommunity, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		zlog_debug("%s: post merge static_attr.ecommunity{%s}", __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	/* Nexthop */
	/* if policy nexthop not set, use 0 */
	int nexthop_self_flag = 0;
	if (CHECK_FLAG(bgp_vrf->srv6vpn_policy[afi].flags, BGP_SRV6VPN_POLICY_TOVPN_NEXTHOP_SET)) {
		struct prefix *nexthop = &bgp_vrf->srv6vpn_policy[afi].tovpn_nexthop;

		switch (nexthop->family) {
		case AF_INET:
			/* prevent mp_nexthop_global_in <- self in bgp_route.c
			 */
			static_attr.nexthop.s_addr = nexthop->u.prefix4.s_addr;
			static_attr.mp_nexthop_global_in = nexthop->u.prefix4;
			static_attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
			break;

		case AF_INET6:
			static_attr.mp_nexthop_global = nexthop->u.prefix6;
			static_attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
			break;

		default:
			assert(0);
		}
	} else {
		if (!CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
				BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			if (afi == AFI_IP) {
				/*
				 * For ipv4, copy to multiprotocol
				 * nexthop field
				 */
				static_attr.mp_nexthop_global_in = static_attr.nexthop;
				static_attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
				/*
				 * XXX Leave static_attr.nexthop
				 * intact for NHT
				 */
				static_attr.flag &= ~ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
			}
		} else {
			/* Update based on next-hop family to account for
			 * RFC 5549 (BGP unnumbered) scenario. Note that
			 * specific action is only needed for the case of
			 * IPv4 nexthops as the attr has been copied
			 * otherwise.
			 */
			if (afi == AFI_IP
			    && !BGP_ATTR_NEXTHOP_AFI_IP6(path_vrf->attr)) {
				static_attr.mp_nexthop_global_in.s_addr = static_attr.nexthop.s_addr;
				static_attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
				static_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
			}
		}
		nexthop_self_flag = 1;
	}

	/*
	 * THIS IS DOCUMENTED I-D
	 * https://tools.ietf.org/html/draft-dawra-idr-srv6-vpn-05
	 */
	mpls_label_t label;
	uint8_t *pnt = (uint8_t*)&label;
	*pnt++ = (MPLS_LABEL_IMPLICIT_NULL >> 12) & 0xff;
	*pnt++ = (MPLS_LABEL_IMPLICIT_NULL >> 4) & 0xff;
	*pnt++ = ((MPLS_LABEL_IMPLICIT_NULL << 4) + 1) & 0xff;

	/* Set originator ID to "me" */
	SET_FLAG(static_attr.flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID));
	static_attr.originator_id = bgp_vpn->router_id;


	new_attr = bgp_attr_intern(&static_attr);	/* hashed refcounted everything */
	bgp_attr_flush(&static_attr); /* free locally-allocated parts */

	/* Set SID value on new_attr*/
	memcpy(&new_attr->sid, &bgp_vrf->srv6vpn_policy[afi].tovpn_sid, 16);

	if (debug && new_attr->ecommunity) {
		char *s = ecommunity_ecom2str(new_attr->ecommunity, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		zlog_debug("%s: new_attr->ecommunity{%s}", __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	/* Now new_attr is an allocated interned attr */

	safi_t safi = SAFI_SRV6_VPN;
	bn = bgp_afi_node_get(bgp_vpn->rib[afi][safi], afi, safi, p,
			      &(bgp_vrf->srv6vpn_policy[afi].tovpn_rd));

	struct bgp_path_info *new_info;

	new_info = leak_update(bgp_vpn, bn, new_attr, afi, safi, path_vrf,
			       &label, 1, path_vrf, bgp_vrf, NULL,
			       nexthop_self_flag, debug);

	/*
	 * Routes actually installed in the vpn RIB must also be
	 * offered to all vrfs (because now they originate from
	 * the vpn RIB).
	 *
	 * Acceptance into other vrfs depends on rt-lists.
	 * Originating vrf will not accept the looped back route
	 * because of loop checking.
	 */
	if (new_info) {
		zlog_debug("%s: new_info exist.", __func__);
		srv6vpn_leak_to_vrf_update(bgp_vrf, new_info);
	}
}

void srv6vpn_leak_from_vrf_withdraw(struct bgp *bgp_vpn,		/* to */
				struct bgp *bgp_vrf,		/* from */
				struct bgp_path_info *path_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct prefix *p = &path_vrf->net->p;
	afi_t afi = family2afi(p->family);
	safi_t safi = SAFI_SRV6_VPN;
	struct bgp_path_info *bpi;
	struct bgp_node *bn;
	const char *debugmsg;
	char buf_prefix[PREFIX_STRLEN];

	if (debug) {
		prefix2str(p, buf_prefix, sizeof(buf_prefix));
		zlog_debug(
			"%s: entry: leak-from=%s, p=%s, type=%d, sub_type=%d",
			__func__, bgp_vrf->name_pretty, buf_prefix,
			path_vrf->type, path_vrf->sub_type);
	}

	if (!bgp_vpn)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	/* Is this route exportable into the VPN table? */
	if (!is_route_injectable_into_srv6vpn(path_vrf))
		return;

	if (!srv6vpn_leak_to_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	if (debug)
		zlog_debug("%s: withdrawing (path_vrf=%p)", __func__, path_vrf);

	bn = bgp_afi_node_get(bgp_vpn->rib[afi][safi], afi, safi, p,
			      &(bgp_vrf->srv6vpn_policy[afi].tovpn_rd));

	if (!bn)
		return;
	/*
	 * vrf -> vpn
	 * match original bpi imported from
	 */
	for (bpi = bgp_node_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->parent == path_vrf) {
			break;
		}
	}

	if (bpi) {
		/* withdraw from looped vrfs as well */
		srv6vpn_leak_to_vrf_withdraw(bgp_vpn, bpi);

		bgp_aggregate_decrement(bgp_vpn, p, bpi, afi, safi);
		bgp_path_info_delete(bn, bpi);
		bgp_process(bgp_vpn, bn, afi, safi);
	}
	bgp_unlock_node(bn);
}

void srv6vpn_leak_from_vrf_update_all(struct bgp *bgp_vpn, /* to */
				  struct bgp *bgp_vrf, /* from */
				  afi_t afi)
{
	struct bgp_node *bn;
	struct bgp_path_info *bpi;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);

	if (debug)
		zlog_debug("%s: entry, afi=%d, vrf=%s", __func__, afi,
			   bgp_vrf->name_pretty);

	for (bn = bgp_table_top(bgp_vrf->rib[afi][SAFI_UNICAST]); bn;
	     bn = bgp_route_next(bn)) {

		if (debug)
			zlog_debug("%s: node=%p", __func__, bn);

		for (bpi = bgp_node_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (debug)
				zlog_debug(
					"%s: calling srv6vpn_leak_from_vrf_update",
					__func__);
			srv6vpn_leak_from_vrf_update(bgp_vpn, bgp_vrf, bpi);
		}
	}
}

void srv6vpn_leak_from_vrf_withdraw_all(struct bgp *bgp_vpn, /* to */
				    struct bgp *bgp_vrf, /* from */
				    afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct bgp_node *prn;
	safi_t safi = SAFI_SRV6_VPN;

	/*
	 * Walk vpn table, delete bpi with bgp_orig == bgp_vrf
	 */
	for (prn = bgp_table_top(bgp_vpn->rib[afi][safi]); prn;
	     prn = bgp_route_next(prn)) {

		struct bgp_table *table;
		struct bgp_node *bn;
		struct bgp_path_info *bpi;

		/* This is the per-RD table of prefixes */
		table = bgp_node_get_bgp_table_info(prn);

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {

			char buf[PREFIX2STR_BUFFER];

			bpi = bgp_node_get_bgp_path_info(bn);
			if (debug && bpi) {
				zlog_debug(
					"%s: looking at prefix %s", __func__,
					prefix2str(&bn->p, buf, sizeof(buf)));
			}

			for (; bpi; bpi = bpi->next) {
				if (debug)
					zlog_debug("%s: type %d, sub_type %d",
						   __func__, bpi->type,
						   bpi->sub_type);
				if (bpi->sub_type != BGP_ROUTE_IMPORTED)
					continue;
				if (!bpi->extra)
					continue;
				if ((struct bgp *)bpi->extra->bgp_orig
				    == bgp_vrf) {
					/* delete route */
					if (debug)
						zlog_debug("%s: deleting it",
							   __func__);
					bgp_aggregate_decrement(bgp_vpn, &bn->p,
								bpi, afi, safi);
					bgp_path_info_delete(bn, bpi);
					bgp_process(bgp_vpn, bn, afi, safi);
				}
			}
		}
	}
}

void srv6vpn_leak_to_vrf_update_all(struct bgp *bgp_vrf, /* to */
				struct bgp *bgp_vpn, /* from */
				afi_t afi)
{
	struct prefix_rd prd;
	safi_t safi = SAFI_SRV6_VPN;

	assert(bgp_vpn);

	/*
	 * Walk vpn table
	 */
	for (struct bgp_node *prn = bgp_table_top(bgp_vpn->rib[afi][safi]);
			 prn; prn = bgp_route_next(prn)) {

		memset(&prd, 0, sizeof(prd));
		prd.family = AF_UNSPEC;
		prd.prefixlen = 64;
		memcpy(prd.val, prn->p.u.val, 8);

		/* This is the per-RD table of prefixes */
		struct bgp_table *table = bgp_node_get_bgp_table_info(prn);

		if (!table)
			continue;

		for (struct bgp_node *bn = bgp_table_top(table);
				 bn; bn = bgp_route_next(bn)) {

			for (struct bgp_path_info *bpi = bgp_node_get_bgp_path_info(bn);
					 bpi; bpi = bpi->next) {

				if (bpi->extra && bpi->extra->bgp_orig == bgp_vrf) {
					continue;
				}

				srv6vpn_leak_to_vrf_update_onevrf(bgp_vrf, bgp_vpn, bpi);
			}
		}
	}
}

void srv6vpn_leak_to_vrf_withdraw_all(struct bgp *bgp_vrf, /* to */
				  afi_t afi)
{
	struct bgp_node *bn;
	struct bgp_path_info *bpi;
	safi_t safi = SAFI_UNICAST;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: entry", __func__);
	/*
	 * Walk vrf table, delete bpi with bgp_orig in a different vrf
	 */
	for (bn = bgp_table_top(bgp_vrf->rib[afi][safi]); bn;
	     bn = bgp_route_next(bn)) {

		for (bpi = bgp_node_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (bpi->extra
			    && bpi->extra->bgp_orig != bgp_vrf
			    && bpi->extra->parent
			    && is_pi_family_srv6vpn(bpi->extra->parent)) {

				/* delete route */
				bgp_aggregate_decrement(bgp_vrf, &bn->p, bpi,
							afi, safi);
				bgp_path_info_delete(bn, bpi);
				bgp_process(bgp_vrf, bn, afi, safi);
			}
		}
	}
}

int vpn_leak_sid_callback(
	struct in6_addr *sid,
	void *labelid,
	bool allocated)
{
	zlog_err(C_RED "%s(slankdev) THIS FUNCTION IS NOT IMPLEMENTED" C_DEF, __func__);
	return 0;
#if 0
	struct vpn_policy *vp = (struct vpn_policy *)labelid;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (debug)
		zlog_debug("%s: label=%u, allocated=%d",
			__func__, label, allocated);

	if (!allocated) {
		/*
		 * previously-allocated label is now invalid
		 */
		if (CHECK_FLAG(vp->flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO) &&
			(vp->tovpn_label != MPLS_LABEL_NONE)) {

			vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN,
				vp->afi, bgp_get_default(), vp->bgp);
			vp->tovpn_label = MPLS_LABEL_NONE;
			vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN,
				vp->afi, bgp_get_default(), vp->bgp);
		}
		return 0;
	}

	/*
	 * New label allocation
	 */
	if (!CHECK_FLAG(vp->flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {

		/*
		 * not currently configured for auto label, reject allocation
		 */
		return -1;
	}

	if (vp->tovpn_label != MPLS_LABEL_NONE) {
		if (label == vp->tovpn_label) {
			/* already have same label, accept but do nothing */
			return 0;
		}
		/* Shouldn't happen: different label allocation */
		flog_err(EC_BGP_LABEL,
			 "%s: %s had label %u but got new assignment %u",
			 __func__, vp->bgp->name_pretty, vp->tovpn_label,
			 label);
		/* use new one */
	}

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN,
		vp->afi, bgp_get_default(), vp->bgp);
	vp->tovpn_label = label;
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN,
		vp->afi, bgp_get_default(), vp->bgp);

	return 0;
#endif
}

int bgp_nlri_parse_srv6vpn(struct peer *peer, struct attr *attr,
		       struct bgp_nlri *packet)
{
	uint8_t *pnt = packet->nlri;
	uint8_t *lim = pnt + packet->length;
	afi_t afi = packet->afi;
	safi_t safi = packet->safi;
	uint32_t addpath_id = 0;

	int addpath_encoded =
		(CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV)
		 && CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV));

	const int VPN_PREFIXLEN_MIN_BYTES = (3 + 8); /* label + RD */
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	int psize = 0;
	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		struct prefix p;
		memset(&p, 0, sizeof(struct prefix));

		if (addpath_encoded) {

			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			addpath_id = ntohl(*((uint32_t *)pnt));
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length. */
		int prefixlen = *pnt++;
		p.family = afi2family(packet->afi);
		psize = PSIZE(prefixlen);

		if (prefixlen < VPN_PREFIXLEN_MIN_BYTES * 8) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (prefix length %d less than VPN min length)",
				peer->host, prefixlen);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
		}

		/* sanity check against packet data */
		if ((pnt + psize) > lim) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (prefix length %d exceeds packet size %u)",
				peer->host, prefixlen, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* sanity check against storage for the IP address portion */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > (ssize_t)sizeof(p.u)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (psize %d exceeds storage size %zu)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				sizeof(p.u));
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		/* Sanity check against max bitlen of the address family */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > prefix_blen(&p)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (psize %d exceeds family (%u) max byte len %u)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				p.family, prefix_blen(&p));
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		/* Copy label to prefix. */
		mpls_label_t label = {0};
		memcpy(&label, pnt, BGP_LABEL_BYTES);
		bgp_set_valid_label(&label);

		/* Make prefix_rd */
		struct prefix_rd prd;
		prd.family = AF_UNSPEC;
		prd.prefixlen = 64;

		/* Copy routing distinguisher to rd. */
		memcpy(&prd.val, pnt + BGP_LABEL_BYTES, 8);

		/* Decode RD type. */
		uint16_t type = decode_rd_type(pnt + BGP_LABEL_BYTES);

		switch (type) {
		case RD_TYPE_AS:
			decode_rd_as(pnt + 5, &rd_as);
			break;

		case RD_TYPE_AS4:
			decode_rd_as4(pnt + 5, &rd_as);
			break;

		case RD_TYPE_IP:
			decode_rd_ip(pnt + 5, &rd_ip);
			break;

		default:
			flog_err(EC_BGP_UPDATE_RCV, "Unknown RD type %d", type);
			break; /* just report */
		}

		p.prefixlen =
			prefixlen
			- VPN_PREFIXLEN_MIN_BYTES * 8; /* exclude label & RD */
		memcpy(p.u.val, pnt + VPN_PREFIXLEN_MIN_BYTES,
		       psize - VPN_PREFIXLEN_MIN_BYTES);

		if (attr) {
			bgp_update(peer, &p, addpath_id, attr, packet->afi,
				   SAFI_SRV6_VPN, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, &prd, &label, 1, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, addpath_id, attr, packet->afi,
				     SAFI_SRV6_VPN, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, &prd, &label, 1, NULL);
		}
	}
	/* Packet length consistency check. */
	if (pnt != lim) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / VPN (%zu data remaining after parsing)",
			peer->host, lim - pnt);
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
	}

	return 0;
}
