#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

int main()
{
	int ret;
	struct nfct_handle *h;
	struct nf_conntrack *master, *expected, *mask;
	struct nf_expect *exp;

	/*
	 * Step 1: Setup master conntrack
	 */

	master = nfct_new();
	if (!master) {
		perror("nfct_new");
		exit(EXIT_FAILURE);
	}

	nfct_set_attr_u8(master, ATTR_L3PROTO, AF_INET);
	nfct_set_attr_u32(master, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
	nfct_set_attr_u32(master, ATTR_IPV4_DST, inet_addr("2.2.2.2"));

	nfct_set_attr_u8(master, ATTR_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(master, ATTR_PORT_SRC, htons(1025));
	nfct_set_attr_u16(master, ATTR_PORT_DST, htons(21));

	nfct_setobjopt(master, NFCT_SOPT_SETUP_REPLY);

	nfct_set_attr_u8(master, ATTR_TCP_STATE, TCP_CONNTRACK_LISTEN);
	nfct_set_attr_u32(master, ATTR_TIMEOUT, 200);

	h = nfct_open(CONNTRACK, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfct_query(h, NFCT_Q_CREATE, master);

	printf("TEST: add master conntrack (%d)(%s)\n", ret, strerror(errno));

	nfct_close(h);

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

	mask = nfct_new();
	if (!mask) {
		perror("nfct_new");
		exit(EXIT_FAILURE);
	}

	nfct_set_attr_u8(mask, ATTR_L3PROTO, AF_INET);
	nfct_set_attr_u32(mask, ATTR_IPV4_SRC, 0xffffffff);
	nfct_set_attr_u32(mask, ATTR_IPV4_DST, 0xffffffff);

	nfct_set_attr_u8(mask, ATTR_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(mask, ATTR_PORT_SRC, 0xffff);
	nfct_set_attr_u16(mask, ATTR_PORT_DST, 0xffff);

	/*
	 * Step 2: Setup expectation
	 */
	
	exp = nfexp_new();
	if (!exp) {
		perror("nfexp_new");
		exit(EXIT_FAILURE);
	}

	nfexp_set_attr(exp, ATTR_EXP_MASTER, master);
	nfexp_set_attr(exp, ATTR_EXP_EXPECTED, expected);
	nfexp_set_attr(exp, ATTR_EXP_MASK, mask);
	nfexp_set_attr_u32(exp, ATTR_EXP_TIMEOUT, 200);

	nfct_destroy(master);
	nfct_destroy(expected);
	nfct_destroy(mask);

	h = nfct_open(EXPECT, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfexp_query(h, NFCT_Q_CREATE, exp);

	printf("TEST: create expectation (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
