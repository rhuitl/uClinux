#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int cb(enum nf_conntrack_msg_type type,
	      struct nf_conntrack *ct,
	      void *data)
{
	char buf[1024];

	nfct_snprintf(buf, 1024, ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

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

	nfct_callback_register(h, NFCT_T_ALL, cb, NULL);
	ret = nfct_query(h, NFCT_Q_DUMP, &family);

	printf("TEST: dump conntrack (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	nfct_close(h);
}
