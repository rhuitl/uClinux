# Kernel sources
# $Id: Makefile,v 0.15 1998/11/25 19:03:26 jjo Exp $
# 
# If you need to pass extra flags: (eg to compile w/libc5 on libc6 system)
#    make XCFLAGS="-I/usr/i486-linux-libc5/include"
#
VERSION=0.4.2

include Common.mk

SUBDIRS :=lib modules ipmasqadm
.PHONY: $(SUBDIRS)

all : check_kernel_headers_directory $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

check_kernel_headers_directory:
	@test -f $(KSRC)/include/linux/ip_masq.h

test : all modules
	env LD_LIBRARY_PATH=./modules ./ipmasqadm testmod

install: #all
	@mkdir -p $(LIBDIR) 2>/dev/null; chmod 700 $(LIBDIR)
	@mkdir -p $(SBIN) 2>/dev/null
	@mkdir -p $(MANDIR)/man8 2>/dev/null
	install -m 700 -o root -g root modules/*.so $(LIBDIR)
	install -m 700 -o root -g root ipmasqadm/ipmasqadm $(SBIN)
	install -m 644 -o root -g root man/ipmasqadm.8 $(MANDIR)/man8

romfs:
	for i in modules/*.so; do \
		$(ROMFSINST) $$i $(LIBDIR)/`basename $$i`; \
	done
	$(ROMFSINST) ipmasqadm/ipmasqadm $(SBIN)/ipmasqadm

dist: cleanall
	tar -C .. --exclude RCS -zcvf ../ipmasqadm-$(VERSION).tar.gz ipmasqadm-$(VERSION)

cleanall: clean
	rm -f *~
clean:
	@for i in $(SUBDIRS);do $(MAKE) -C $$i $@;done
	#rm -f ipmasqadm *.o *.so core

