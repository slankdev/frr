
#include "srv6.h"
#include "log.h"

int snprintf_seg6_segs(char *str,
		size_t size, const struct seg6_segs *segs)
{
	char buf[128] = {0};
	size_t len = 0;
	for (size_t i=0; i<segs->num_segs; i++) {
		char addr[128];
		inet_ntop(AF_INET6, &segs->segs[i], addr, 128);
		snprintf(&buf[len], 128-len, "%s%s",
				addr, i+1<segs->num_segs?",":"");
		len = strlen(buf);
	}
	return snprintf(str, size, "%s", buf);
}

extern const char*
seg6local_context2str(char *str, size_t size,
		struct seg6local_context *ctx, uint32_t action)
{
	char b0[128];
	switch (action) {

		case SEG6_LOCAL_ACTION_END:
			snprintf(str, size, "USP");
			return str;

		case SEG6_LOCAL_ACTION_END_X:
		case SEG6_LOCAL_ACTION_END_DX6:
			inet_ntop(AF_INET6, &ctx->nh6, b0, 128);
			snprintf(str, size, "nh6 %s", b0);
			return str;

		case SEG6_LOCAL_ACTION_END_DX4:
			inet_ntop(AF_INET, &ctx->nh4, b0, 128);
			snprintf(str, size, "nh4 %s", b0);
			return str;

		case SEG6_LOCAL_ACTION_END_T:
		case SEG6_LOCAL_ACTION_END_DT6:
		case SEG6_LOCAL_ACTION_END_DT4:
			snprintf(str, size, "table %u", ctx->table);
			return str;

		case SEG6_LOCAL_ACTION_END_DX2:
		case SEG6_LOCAL_ACTION_END_B6:
		case SEG6_LOCAL_ACTION_END_B6_ENCAP:
		case SEG6_LOCAL_ACTION_END_BM:
		case SEG6_LOCAL_ACTION_END_S:
		case SEG6_LOCAL_ACTION_END_AS:
		case SEG6_LOCAL_ACTION_END_AM:
		case SEG6_LOCAL_ACTION_UNSPEC:
		default:
			snprintf(str, size, "unknown(%s)", __func__);
			return str;
	}
}
