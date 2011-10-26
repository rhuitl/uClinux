#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int cb(enum nf_conntrack_msg_type type,
	      struct nf_expect *exp,
	      void *data)
{
	char buf[1024];

	nfexp_snprintf(buf, 1024, exp, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

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

	nfexp_callback_register(h, NFCT_T_ALL, cb, NULL);
	ret = nfexp_query(h, NFCT_Q_DUMP, &family);

	printf("TEST: get expectation (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
