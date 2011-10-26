all:
	$(MAKE) -f Makefile binaries

romfs:
	$(MAKE) -f Makefile binaries_romfs

clean:
	$(MAKE) -f Makefile binaries_clean

.PHONY: kernel
kernel:
	cp kernel/*.c ../../linux-2.6.x/net/ipv4/netfilter/
	cp kernel/include/linux/netfilter_ipv4/*.h ../../linux-2.6.x/include/linux/netfilter_ipv4/

.PHONY: iptables
iptables:
	cp kernel/include/linux/netfilter_ipv4/ipt_set.h ../iptables/include/linux/netfilter_ipv4/

