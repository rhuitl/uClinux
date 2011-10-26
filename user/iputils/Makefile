# Path to parent kernel include files directory
KERNEL_INCLUDE=$(ROOTDIR)/$(LINUXDIR)/include
LIBC_INCLUDE=$(ROOTDIR)/$(LIBCDIR)/include
BINDIR=/bin

DEFINES= 

#options if you have a bind>=4.9.4 libresolv (or, maybe, glibc)
LDLIBS+=-lresolv
ADDLIB=

#options if you compile with libc5, and without a bind>=4.9.4 libresolv
# NOT AVAILABLE. Please, use libresolv.

#CC=gcc
# What a pity, all new gccs are buggy and -Werror does not work. Sigh.
#CCOPT=-D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall -g -Werror
CCOPT=-D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall -g
CFLAGS=$(CCOPT) $(GLIBCFIX) $(DEFINES) 

IPV4_TARGETS=tracepath ping clockdiff rdisc arping tftpd rarpd
IPV6_TARGETS=tracepath6 traceroute6 ping6
TARGETS=$(IPV4_TARGETS) $(IPV6_TARGETS)
CLEAN_TARGETS:=$(TARGETS)

ifneq ($(CONFIG_USER_IPUTILS_RARPD),y)
TARGETS:=$(filter-out rarpd, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_TFTPD),y)
TARGETS:=$(filter-out tftpd, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_ARPING),y)
TARGETS:=$(filter-out arping, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_RDISC),y)
TARGETS:=$(filter-out rdisc, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_CLOCKDIFF),y)
TARGETS:=$(filter-out clockdiff, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_PING),y)
TARGETS:=$(filter-out ping, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_TRACEPATH),y)
TARGETS:=$(filter-out tracepath, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_PING6),y)
TARGETS:=$(filter-out ping6, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_TRACEROUTE6),y)
TARGETS:=$(filter-out traceroute6, $(TARGETS))
endif
ifneq ($(CONFIG_USER_IPUTILS_TRACEPATH6),y)
TARGETS:=$(filter-out tracepath6, $(TARGETS))
endif

LASTTAG:=`git-describe HEAD | sed -e 's/-.*//'`
TAG:=`date +s%Y%m%d`

all: $(TARGETS)

tftpd: tftpd.o tftpsubs.o
ping: ping.o ping_common.o
ping6: ping6.o ping_common.o
ping.o ping6.o ping_common.o: ping_common.h
tftpd.o tftpsubs.o: tftp.h

rdisc_srv: rdisc_srv.o

rdisc_srv.o: rdisc.c
	$(CC) $(CFLAGS) -DRDISC_SERVER -o rdisc_srv.o rdisc.c


check-kernel:
ifeq ($(KERNEL_INCLUDE),)
	@echo "Please, set correct KERNEL_INCLUDE"; false
else
	@set -e; \
	if [ ! -r $(KERNEL_INCLUDE)/linux/autoconf.h ]; then \
		echo "Please, set correct KERNEL_INCLUDE"; false; fi
endif

modules: check-kernel
	$(MAKE) KERNEL_INCLUDE=$(KERNEL_INCLUDE) -C Modules

man:
	$(MAKE) -C doc man

html:
	$(MAKE) -C doc html

clean:
	@rm -f *.o $(CLEAN_TARGETS)
	@$(MAKE) -C Modules clean
	@$(MAKE) -C doc clean

snapshot:
	@if [ "`uname -n`" != "berry" ]; then echo "Not authorized to advance snapshot"; exit 1; fi
	@date "+[$(TAG)]" > RELNOTES.NEW
	@echo >>RELNOTES.NEW
	@git-log $(LASTTAG).. | git-shortlog >> RELNOTES.NEW
	@echo >> RELNOTES.NEW
	@cat RELNOTES >> RELNOTES.NEW
	@mv RELNOTES.NEW RELNOTES
	@date "+static char SNAPSHOT[] = \"$(TAG)\";" > SNAPSHOT.h
	@$(MAKE) -C doc snapshot
	@$(MAKE) man
	@git-commit -a -m "iputils-$(TAG)"
	@git-tag -s -m "iputils-$(TAG)" $(TAG)
	@git-tar-tree $(TAG) iputils-$(TAG) | bzip2 -9 > ../iputils-$(TAG).tar.bz2

romfs:
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_PING6 $(BINDIR)/ping6
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_PING $(BINDIR)/ping
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_TRACEROUTE6 $(BINDIR)/traceroute6
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_RDISC $(BINDIR)/rdisc_srv
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_CLOCKDIFF $(BINDIR)/clockdiff
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_TFTPD $(BINDIR)/tftpd
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_TRACEPATH $(BINDIR)/tracepath
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_TRACEPATH6 $(BINDIR)/tracepath6
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_ARPING $(BINDIR)/arping
	$(ROMFSINST) -e CONFIG_USER_IPUTILS_RARPD $(BINDIR)/rarpd
