#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

int main()
{
	int ret;
	u_int8_t family = AF_INET;
	struct nfct_handle *h;

	h = nfct_open(EXPECT, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfexp_query(h, NFCT_Q_FLUSH, &family);

	printf("TEST: flush expectation (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
