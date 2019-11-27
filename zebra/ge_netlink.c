
#include "zebra/ge_netlink.h"

#include <netinet/if_ether.h>
#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/seg6_genl.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#include <stdio.h>
#include "vty.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"

extern struct zebra_privs_t zserv_privs;

static inline int
nl_talk(int fd, struct nlmsghdr *n,
                struct nlmsghdr *answer, size_t answer_buf_siz)
{
  static char buf[10000];
  if (answer == NULL) {
    n->nlmsg_flags |= NLM_F_ACK;
    answer = (struct nlmsghdr*)buf;
    answer_buf_siz = sizeof(buf);
  }

	frr_with_privs(&zserv_privs) {
		int ret = send(fd, n, n->nlmsg_len, 0);
		if (ret < 0) {
			perror("send");
			exit(1);
		}
		ret = recv(fd, answer, answer_buf_siz, 0);
		if (ret < 0) {
			perror("recv");
			exit(1);
		}
	}
  return 0;
}

extern int ge_netlink_resolve_family(int fd, const char* family_name)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req) - NL_PKT_BUF_SIZE);
	req.n.nlmsg_type = GENL_ID_CTRL;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
	req.g.cmd = CTRL_CMD_GETFAMILY;
	req.g.version = 2;

  addattrstrz(&req.n, 1024, CTRL_ATTR_FAMILY_NAME, family_name);

  char buf[10000];
  struct nlmsghdr *answer = (struct nlmsghdr*)buf;

	int genl_family = -1;
	frr_with_privs(&zserv_privs) {
		if (nl_talk(fd, &req.n, answer, sizeof(buf)) < 0)
			exit(1);
	}

	memcpy(&req, answer, sizeof(req));
	int len = req.n.nlmsg_len;
	if (NLMSG_OK(&req.n, len) ) {
		struct rtattr *rta[CTRL_ATTR_MAX + 1] = {};
		int l = req.n.nlmsg_len - NLMSG_LENGTH(sizeof(struct genlmsghdr));
		netlink_parse_rtattr(rta, CTRL_ATTR_MAX, (struct rtattr*)req.buf, l);

		if(rta[CTRL_ATTR_FAMILY_ID]) {
			uint16_t id = *(uint16_t *)RTA_DATA(rta[CTRL_ATTR_FAMILY_ID]);
			genl_family = id;
		}
	}
	return genl_family;
}

/*
 * Update or delete a srtunsrc from the kernel,
 * using info from a dataplane context.
 */
enum zebra_dplane_result kernel_srtunsrc_update_ctx(struct zebra_dplane_ctx *ctx)
{
	const struct zebra_ns *zns = zebra_ns_lookup(0);
	int genl_family = zns->genl_family_seg6;
	if (genl_family < 0) {
		zlog_err("Failure to resolv SEG6 genl family");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req) - NL_PKT_BUF_SIZE);
	req.n.nlmsg_type = genl_family;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
	req.g.cmd = SEG6_CMD_SET_TUNSRC;
	req.g.version = SEG6_GENL_VERSION;

	addattr_l(&req.n, sizeof(req), SEG6_ATTR_DST,
			dplane_ctx_srtunsrc_get_addr(ctx),
			sizeof(struct in6_addr));

	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_SUCCESS;

#if 0
	result = netlink_talk_info(netlink_talk_filter, &req.n,
			dplane_ctx_get_ns(ctx), 0);
#else
	int fd = zns->genetlink.sock;
	if (nl_talk(fd, &req.n, NULL, 0) < 0)
	 exit(1);
#endif

	return result;
}

void ge_netlink_init(void)
{
}

