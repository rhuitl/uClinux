#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

int main()
{
	int ret;
	struct nfct_handle *h;
	struct nf_conntrack *expected;
	struct nf_expect *exp;

	expected = nfct_new();
	if (!expected) {
		perror("nfct_new");
		exit(EXIT_FAILURE);
	}

	nfct_set_attr_u8(expected, ATTR_L3PROTO, AF_INET);
	nfct_set_attr_u32(expected, ATTR_IPV4_SRC, inet_addr("4.4.4.4"));
	nfct_set_attr_u32(expected, ATTR_IPV4_DST, inet_addr("5.5.5.5"));

	nfct_set_attr_u8(expected, ATTR_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(expected, ATTR_PORT_SRC, htons(10240));
	nfct_set_attr_u16(expected, ATTR_PORT_DST, htons(10241));

	exp = nfexp_new();
	if (!exp) {
		perror("nfexp_new");
		exit(EXIT_FAILURE);
	}

	nfexp_set_attr(exp, ATTR_EXP_EXPECTED, expected);

	h = nfct_open(EXPECT, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfexp_query(h, NFCT_Q_DESTROY, exp);

	printf("TEST: delete expectation (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
