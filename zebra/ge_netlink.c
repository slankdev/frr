
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
#include "zebra/hexdump.h"
#include "zebra/slankdev_netlink.h"

extern struct zebra_privs_t zserv_privs;

static int ge_netlink_resolve_family(int fd, const char* family_name)
{

 GENL_REQUEST(req, 1024, GENL_ID_CTRL, 0,
      2, CTRL_CMD_GETFAMILY, NLM_F_REQUEST);
  addattrstrz(&req.n, 1024, CTRL_ATTR_FAMILY_NAME, family_name);

  char buf[10000];
  struct nlmsghdr *answer = (struct nlmsghdr*)buf;
  if (nl_talk(fd, &req.n, answer, sizeof(buf)) < 0)
    exit(1);

  int genl_family = -1;
  memcpy(&req, answer, sizeof(req));
  int len = req.n.nlmsg_len;
  if (NLMSG_OK(&req.n, len) ) {
    struct rtattr *rta[CTRL_ATTR_MAX + 1] = {};
    int l = req.n.nlmsg_len - NLMSG_LENGTH(sizeof(struct genlmsghdr));
    parse_rtattr(rta, CTRL_ATTR_MAX, (struct rtattr*)req.buf, l);

    if(rta[CTRL_ATTR_FAMILY_ID]) {
      uint16_t id = rta_getattr_u16(rta[CTRL_ATTR_FAMILY_ID]);
      genl_family = id;
    }
  }
	return genl_family;
}

void ge_netlink_sr_tunsrc_change(struct in6_addr *src)
{
	int fd = -1;
	frr_with_privs(&zserv_privs) {
		fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
		if (fd < 0) {
			fprintf(stderr, "open_genetlink_socket; error\n");
			exit(1);
		}

		int genl_family = ge_netlink_resolve_family(fd, "SEG6");
		if (genl_family < 0) {
			fprintf(stderr, "ge_netlink_get_family; error\n");
			exit(1);
		}
		GENL_REQUEST(req, 1024, genl_family, 0, SEG6_GENL_VERSION, SEG6_CMD_SET_TUNSRC, NLM_F_REQUEST);
		addattr_l(&req.n, sizeof(req), SEG6_ATTR_DST, src, sizeof(struct in6_addr));
		if (nl_talk(fd, &req.n, NULL, 0) < 0)
		 exit(1);
	}
	close(fd);
}

