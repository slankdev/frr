
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

#define GENL_REQUEST(_req, _bufsiz, _family, _hdrsiz, _ver, _cmd, _flags) \
struct {                                                \
  struct nlmsghdr    n;                                 \
  struct genlmsghdr  g;                                 \
  char buf[NLMSG_ALIGN(_hdrsiz) + (_bufsiz)];           \
} _req = {                                              \
  .n = {                                                \
    .nlmsg_type = (_family),                            \
    .nlmsg_flags = (_flags),                            \
    .nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + (_hdrsiz)), \
  },                                                    \
  .g = {                                                \
    .cmd = (_cmd),                                      \
    .version = (_ver),                                  \
  },                                                    \
}

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) \
  ((struct rtattr *) (((uint8_t *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

#define RTA_TAIL(rta) \
    ((struct rtattr *) (((uint8_t *) (rta)) + \
            RTA_ALIGN((rta)->rta_len)))


extern struct zebra_privs_t zserv_privs;

static inline int
addattr_l(struct nlmsghdr *n, int maxlen,
    int type, const void *data, int alen)
{
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > (size_t)maxlen) {
    fprintf(stderr,
      "addattr_l ERROR: message exceeded bound of %d\n",
      maxlen);
    return -1;
  }
  rta = NLMSG_TAIL(n);
  rta->rta_type = type;
  rta->rta_len = len;
  if (alen)
    memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  return 0;
}

static inline __u16 rta_getattr_u16(const struct rtattr *rta)
{ return *(__u16 *)RTA_DATA(rta); }

static inline int
addattr(struct nlmsghdr *n, int maxlen, int type)
{ return addattr_l(n, maxlen, type, NULL, 0); }
static inline int
addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data)
{ return addattr_l(n, maxlen, type, &data, sizeof(__u8)); }
static inline int
addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data)
{ return addattr_l(n, maxlen, type, &data, sizeof(__u16)); }
static inline int
addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{ return addattr_l(n, maxlen, type, &data, sizeof(__u32)); }
static inline int
addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data)
{ return addattr_l(n, maxlen, type, &data, sizeof(__u64)); }
static inline int
addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str)
{ return addattr_l(n, maxlen, type, str, strlen(str)+1); }

static inline int
parse_rtattr_flags(struct rtattr *tb[],
    int max, struct rtattr *rta,
    int len, unsigned short flags)
{
  unsigned short type;
  memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
  while (RTA_OK(rta, len)) {
    type = rta->rta_type & ~flags;
    if ((type <= max) && (!tb[type]))
      tb[type] = rta;
    rta = RTA_NEXT(rta, len);
  }
  if (len)
    fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
      len, rta->rta_len);
  return 0;
}

static inline int
parse_rtattr(struct rtattr *tb[],
    int max, struct rtattr *rta, int len)
{ return parse_rtattr_flags(tb, max, rta, len, 0); }

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
  return 0;
}

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

