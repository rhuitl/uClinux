#
# lib/Makefile
#
# 	This library is free software; you can redistribute it and/or
#	modify it under the terms of the GNU Lesser General Public
#	License as published by the Free Software Foundation version 2.1
#	of the License.
#
# Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
#

ifeq ($(shell [ ! -r ../Makefile.opts ] && echo 1),)
    include ../Makefile.opts
endif

# Core
CIN      := $(wildcard *.c)
# NETLINK_ROUTE
CIN      += $(wildcard route/*.c)
# Schedulers
CIN      += $(wildcard route/sch/*.c)
# Classifiers
CIN      += $(wildcard route/cls/*.c)
# Link Info Modules
CIN      += $(wildcard route/link/*.c)
# NETLINK_GENERIC
CIN      += $(wildcard genl/*.c)
# fib lookup
CIN      += $(wildcard fib_lookup/*.c)
# Netfilter
CIN      += $(wildcard netfilter/*.c)

ALLCIN := $(CIN)
ifdef CONFIG_LIB_LIBNL_COMPONENTS
# Core
CIN      := $(wildcard *.c)
# NETLINK_ROUTE
ifdef CONFIG_LIB_LIBNL_RTNL
CIN      += $(wildcard route/rtnl.c)
endif
ifdef CONFIG_LIB_LIBNL_ROUTE_ADDR
CIN      += $(wildcard route/addr.c)
endif
ifdef CONFIG_LIB_LIBNL_ROUTE_LINK
CIN      += $(wildcard route/link.c)
# Link Info Modules
CIN      += $(wildcard route/link/*.c)
endif
ifdef CONFIG_LIB_LIBNL_ROUTE_NEIGH
CIN      += $(wildcard route/neigh*.c)
endif
ifdef CONFIG_LIB_LIBNL_ROUTE_ROUTE
CIN      += $(wildcard route/route*.c)
CIN      += $(wildcard route/nexthop.c)
endif
ifdef CONFIG_LIB_LIBNL_ROUTE_RULE
CIN      += $(wildcard route/rule.c)
endif
ifdef CONFIG_LIB_LIBNL_ROUTE_TC
CIN      += $(wildcard route/class*.c)
CIN      += $(wildcard route/cls*.c)
CIN      += $(wildcard route/qdisc*.c)
CIN      += $(wildcard route/tc.c)
# Schedulers
CIN      += $(wildcard route/sch/*.c)
# Classifiers
CIN      += $(wildcard route/cls/*.c)
endif
# NETLINK_GENERIC
ifdef CONFIG_LIB_LIBNL_GENERIC
CIN      += $(wildcard genl/*.c)
endif
# fib lookup
ifdef CONFIG_LIB_LIBNL_FIB
CIN      += $(wildcard fib_lookup/*.c)
endif
# Netfilter
ifdef CONFIG_LIB_LIBNL_NETFILTER
CIN      += $(wildcard netfilter/netfilter.c)
CIN      += $(wildcard netfilter/nfnl.c)
endif
ifdef CONFIG_LIB_LIBNL_NETFILTER_CT
CIN      += $(wildcard netfilter/ct*.c)
endif
ifdef CONFIG_LIB_LIBNL_NETFILTER_LOG
CIN      += $(wildcard netfilter/log*.c)
endif
ifdef CONFIG_LIB_LIBNL_NETFILTER_QUEUE
CIN      += $(wildcard netfilter/queue*.c)
endif
endif

DEPS     := $(CIN:%.c=%.d)
ALLDEPS  := $(ALLCIN:%.c=%.d)
OBJ      := $(CIN:%.c=%.o)
ALLOBJ   := $(ALLCIN:%.c=%.o)
CFLAGS   += -fPIC
OUT_SLIB := $(PACKAGE_NAME).so.$(PACKAGE_VERSION)
LN_SLIB  := $(PACKAGE_NAME).so
LN1_SLIB := $(LN_SLIB).1

export

.PHONY: all clean install librtn.a $(OUT_SLIB)


all:
	@echo "  MAKE $(OUT_SLIB)"; \
	$(MAKE) $(OUT_SLIB)

$(OUT_SLIB): ../Makefile.opts $(OBJ)
	@echo "  LD $(OUT_SLIB)"; \
	$(CC) -shared -Wl,-soname,libnl.so.1 -o $(OUT_SLIB) $(OBJ) $(LIBNL_LIB) -lc
	@echo "  LN $(OUT_SLIB) $(LN1_SLIB)"; \
	rm -f $(LN1_SLIB) ; $(LN) -s $(OUT_SLIB) $(LN1_SLIB)
	@echo "  LN $(LN1_SLIB) $(LN_SLIB)"; \
	rm -f $(LN_SLIB) ; $(LN) -s $(LN1_SLIB) $(LN_SLIB)

clean:
	@echo "  CLEAN lib"; \
	$(RM) -f $(ALLOBJ) $(OUT_SLIB) $(LN_SLIB) $(LN1_SLIB); \
	$(RM) -f $(ALLDEPS) $(OUT_SLIB) $(LN_SLIB) $(LN1_SLIB)

distclean:
	@echo "  DISTCLEAN lib"; \
	$(RM) -f $(ALLDEPS)

install:
	mkdir -p $(DESTDIR)$(libdir)/
	install -m 0644 $(OUT_SLIB) $(DESTDIR)$(libdir)
	rm -f $(DESTDIR)$(libdir)/$(LN1_SLIB)
	$(LN) -s $(OUT_SLIB) $(DESTDIR)$(libdir)/$(LN1_SLIB)
	rm -f $(DESTDIR)$(libdir)/$(LN_SLIB)
	$(LN) -s $(LN1_SLIB) $(DESTDIR)$(libdir)/$(LN_SLIB)

$(DEPS): ../Makefile.opts

include ../Makefile.rules
