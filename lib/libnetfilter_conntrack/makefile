CONFOPTS = --prefix=
VERSION = 0.0.81

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/.libs/libnetfilter_conntrack.so.1 /lib/libnetfilter_conntrack.so.1
	$(ROMFSINST) -d build/extensions/.libs/nfct_proto_tcp-$(VERSION).so /lib/libnetfilter_conntrack/nfct_proto_tcp-$(VERSION).so
	$(ROMFSINST) build/extensions/.libs/nfct_proto_udp-$(VERSION).so /lib/libnetfilter_conntrack/nfct_proto_udp-$(VERSION).so
	$(ROMFSINST) build/extensions/.libs/nfct_proto_icmp-$(VERSION).so /lib/libnetfilter_conntrack/nfct_proto_icmp-$(VERSION).so
	$(ROMFSINST) -e CONFIG_IP_NF_CT_PROTO_SCTP build/extensions/.libs/nfct_proto_sctp-$(VERSION).so /lib/libnetfilter_conntrack/nfct_proto_sctp-$(VERSION).so
	$(ROMFSINST) build/l3extensions/.libs/nfct_l3proto_ipv4-$(VERSION).so /lib/libnetfilter_conntrack/nfct_l3proto_ipv4-$(VERSION).so
	$(ROMFSINST) -e CONFIG_NF_CONNTRACK_IPV6 build/l3extensions/.libs/nfct_l3proto_ipv6-$(VERSION).so /lib/libnetfilter_conntrack/nfct_l3proto_ipv6-$(VERSION).so
