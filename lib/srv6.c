
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

