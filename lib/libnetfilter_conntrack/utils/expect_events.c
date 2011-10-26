#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_expect *exp,
		    void *data)
{
	static int n = 0;
	char buf[1024];

	nfexp_snprintf(buf, 1024, exp, type, NFCT_O_DEFAULT, 0);
	printf("%s\n", buf);

	if (++n == 10)
		return NFCT_CB_STOP;

	return NFCT_CB_CONTINUE;
}

int main()
{
	int ret;
	struct nfct_handle *h;

	h = nfct_open(EXPECT, NF_NETLINK_CONNTRACK_EXP_NEW);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	nfexp_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	printf("TEST: waiting for 10 expectation events...\n");

	ret = nfexp_catch(h);

	printf("TEST: OK (%d)(%s)\n", ret, strerror(errno));

	nfct_close(h);

	if (ret == -1)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
