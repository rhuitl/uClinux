#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

int main()
{
	int ret;
	u_int8_t family = AF_INET;
	struct nfct_handle *h;
	char buf[1024];

	h = nfct_open(CONNTRACK, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfct_query(h, NFCT_Q_FLUSH, &family);

	printf("TEST: flush conntrack (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	nfct_close(h);
}
