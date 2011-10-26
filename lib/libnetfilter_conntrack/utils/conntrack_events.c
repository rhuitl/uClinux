#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data)
{
	static int n = 0;
	char buf[1024];

	nfct_snprintf(buf, 1024, ct, type, NFCT_O_XML, 0);
	printf("%s\n", buf);

	if (++n == 10)
		return NFCT_CB_STOP;

	return NFCT_CB_CONTINUE;
}

int main()
{
	int ret;
	u_int8_t family = AF_INET;
	struct nfct_handle *h;
	struct nf_conntrack *ct;
	char buf[1024];

	h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
	if (!h) {
		perror("nfct_open");
		return 0;
	}

	nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	printf("TEST: waiting for 10 events...\n");

	ret = nfct_catch(h);

	printf("TEST: OK (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	nfct_close(h);
}
