#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

int main()
{
	int ret;
	struct nfct_handle *h;
	struct nf_conntrack *ct;

	ct = nfct_new();
	if (!ct) {
		perror("nfct_new");
		return 0;
	}

	nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
	nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
	nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
	
	nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
	nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
	nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));

	nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

	nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_LISTEN);
	nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

	nfct_set_attr_u32(ct, ATTR_SNAT_IPV4, inet_addr("8.8.8.8"));

	h = nfct_open(CONNTRACK, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}

	ret = nfct_query(h, NFCT_Q_CREATE, ct);

	printf("TEST: create conntrack (%d)(%s)\n", ret, strerror(errno));

	if (ret == -1)
		exit(EXIT_FAILURE);

	nfct_close(h);
}
