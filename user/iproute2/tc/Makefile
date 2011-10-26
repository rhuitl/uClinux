TCOBJ= tc.o tc_qdisc.o tc_class.o tc_filter.o tc_util.o \
       tc_monitor.o m_police.o m_estimator.o m_action.o
ifdef CONFIG_NET_EMATCH
TCOBJ += m_ematch.o emp_ematch.yacc.o emp_ematch.lex.o
endif

include ../Config
SHARED_LIBS ?= y

TCMODULES :=
TCMODULES += q_fifo.o
TCMODULES += q_sfq.o
TCMODULES += q_red.o
TCMODULES += q_prio.o
TCMODULES += q_tbf.o
TCMODULES += q_cbq.o
TCMODULES += q_rr.o
TCMODULES += q_multiq.o
TCMODULES += q_netem.o
TCMODULES += f_rsvp.o
TCMODULES += f_u32.o
TCMODULES += f_route.o
TCMODULES += f_fw.o
TCMODULES += f_basic.o
TCMODULES += f_flow.o
TCMODULES += f_cgroup.o
TCMODULES += q_dsmark.o
TCMODULES += q_gred.o
TCMODULES += f_tcindex.o
TCMODULES += q_ingress.o
TCMODULES += q_hfsc.o
TCMODULES += q_htb.o
TCMODULES += q_drr.o
TCMODULES += m_gact.o
TCMODULES += m_mirred.o
TCMODULES += m_nat.o
TCMODULES += m_pedit.o
TCMODULES += m_skbedit.o
TCMODULES += p_ip.o
TCMODULES += p_icmp.o
TCMODULES += p_tcp.o
TCMODULES += p_udp.o
TCMODULES += em_nbyte.o
TCMODULES += em_cmp.o
TCMODULES += em_u32.o
TCMODULES += em_meta.o

ifdef not_defined

TCSO :=
ifeq ($(TC_CONFIG_ATM),y)
  TCSO += q_atm.so
endif

ifeq ($(TC_CONFIG_XT),y)
  TCSO += m_xt.so
else
  ifeq ($(TC_CONFIG_XT_OLD),y)
    TCSO += m_xt_old.so
  else
    ifeq ($(TC_CONFIG_XT_OLD_H),y)
	CFLAGS += -DTC_CONFIG_XT_H
	TCSO += m_xt_old.so
    else
      TCMODULES += m_ipt.o
    endif
  endif
endif

TCOBJ += $(TCMODULES)

else
lower=$(shell echo $(1) | tr [:upper:] [:lower:])
upper=$(shell echo $(1) | tr [:lower:] [:upper:])
TEST_CONFIG_VAL=$(patsubst $(3)_%,%,$(filter $(3)_%,$(foreach i,$(1),$(CONFIG_$(2)_$(i))_$(i))))
TEST_CONFIG=$(call TEST_CONFIG_VAL,$(1),$(2),y) $(call TEST_CONFIG_VAL,$(1),$(2),m)
NAME_FROM_OBJ=$(call upper,$(patsubst $(2)_%.o,%,$(filter $(2)_%,$(1))))
NAME_TO_OBJ=$(foreach i,$(call lower,$(1)),$(2)_$(i).o)

SCH := $(filter-out FIFO PRIO,$(call NAME_FROM_OBJ,$(TCMODULES),q))
SCH_OPT := $(call TEST_CONFIG,$(SCH),NET_SCH)
TCOBJ += $(call NAME_TO_OBJ,fifo prio $(SCH_OPT),q)

CLS := $(call NAME_FROM_OBJ,$(TCMODULES),f)
CLS_OPT := $(call TEST_CONFIG,$(CLS),NET_CLS)
TCOBJ += $(call NAME_TO_OBJ,$(CLS_OPT),f)

ACT := $(call NAME_FROM_OBJ,$(TCMODULES),m)
ACT_OPT := $(call TEST_CONFIG,$(ACT),NET_ACT)
TCOBJ += $(call NAME_TO_OBJ,$(ACT_OPT),m)

ifdef CONFIG_NET_ACT_PEDIT
TCOBJ += $(filter p_%,$(TCMODULES))
endif

EMATCH := $(call NAME_FROM_OBJ,$(TCMODULES),em)
EMATCH_OPT := $(call TEST_CONFIG,$(EMATCH),NET_EMATCH)
TCOBJ += $(call NAME_TO_OBJ,$(EMATCH_OPT),em)
endif

TCLIB := tc_core.o
TCLIB += tc_red.o
TCLIB += tc_cbq.o
TCLIB += tc_estimator.o
TCLIB += tc_stab.o

CFLAGS += -DCONFIG_GACT -DCONFIG_GACT_PROB
ifneq ($(IPT_LIB_DIR),)
	CFLAGS += -DIPT_LIB_DIR=\"$(IPT_LIB_DIR)\"
endif

LDLIBS += -L. -ltc -lm
ifdef NO_DL
CFLAGS += -DNO_DL
else
ifdef no_defined
ifeq ($(SHARED_LIBS),y)
LDLIBS += -ldl
LDFLAGS += -Wl,-export-dynamic
endif
else
ifeq ($(SHARED_LIBS),y)
LDLIBS := -L. -ltc -lm -ldl $(LDLIBS)
LDFLAGS += -Wl,-export-dynamic
else
LDLIBS := -L. -ltc -lm $(LDLIBS)
endif
endif
endif

YACC := bison
LEX := flex

MODDESTDIR := $(DESTDIR)$(patsubst /usr%,%,$(LIBDIR))/tc

%.so: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fpic $< -o $@


all: libtc.a tc $(TCSO)

tc: $(TCOBJ) $(LIBNETLINK) $(TCLIB)
	$(CC) $(LDFLAGS) -o $@ $(TCOBJ) $(LIBNETLINK) $(TCLIB) $(LDLIBS$(LDLIBS_$@))

tc.o: qdisc.c filter.c

qdisc.c: $(KERNEL_INCLUDE)/../.config Makefile
	@printf "$(foreach i,$(call lower,pfifo bfifo prio $(SCH_OPT)),extern struct qdisc_util $(i)_qdisc_util;\n)" > qdisc.c
	@printf "static struct qdisc_util *qdisc[] = {\n" >> qdisc.c
	@printf "$(foreach i,$(call lower,pfifo bfifo prio $(SCH_OPT)),\t&$(i)_qdisc_util,\n)" >> qdisc.c
	@printf "\tNULL\n};\n" >> qdisc.c

filter.c: $(KERNEL_INCLUDE)/../.config Makefile
	@printf "$(foreach i,$(call lower,$(CLS_OPT)),extern struct filter_util $(i)_filter_util;\n)" > filter.c
	@printf "static struct filter_util *filter[] = {\n" >> filter.c
	@printf "$(foreach i,$(call lower,$(CLS_OPT)),\t&$(i)_filter_util,\n)" >> filter.c
	@printf "\tNULL\n};\n" >> filter.c

romfs:
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_TC_TC /bin/tc

libtc.a: $(TCLIB)
	$(AR) rcs $@ $(TCLIB)

install: all
	mkdir -p $(MODDESTDIR)
	install -m 0755 tc $(DESTDIR)$(SBINDIR)
	for i in $(TCSO); \
	do install -m 755 $$i $(MODDESTDIR); \
	done
	if [ ! -f $(MODDESTDIR)/m_ipt.so ]; then \
	if [ -f $(MODDESTDIR)/m_xt.so ]; \
		then ln -s m_xt.so $(MODDESTDIR)/m_ipt.so ; \
	elif [ -f $(MODDESTDIR)/m_xt_old.so ]; \
		then ln -s m_xt_old.so $(MODDESTDIR)/m_ipt.so ; \
	fi; \
	fi

clean:
	rm -f *.gdb *.o qdisc.c filter.c
	rm -f $(TCOBJ) $(TCLIB) libtc.a tc *.so emp_ematch.yacc.h; \
	rm -f emp_ematch.yacc.output

q_atm.so: q_atm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fpic -o q_atm.so q_atm.c -latm

m_xt.so: m_xt.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fpic -o m_xt.so m_xt.c -lxtables

m_xt_old.so: m_xt_old.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fpic -o m_xt_old.so m_xt_old.c -lxtables

%.yacc.c: %.y
	$(YACC) $(YACCFLAGS) -o $@ $<

%.lex.c: %.l
	$(LEX) $(LEXFLAGS) -o$@ $<

ifneq ($(SHARED_LIBS),y)

tc: static-syms.o
static-syms.o: static-syms.h
static-syms.h: $(wildcard *.c)
	files="$^" ; \
	for s in `grep -B 3 '\<dlsym' $$files | sed -n '/snprintf/{s:.*"\([^"]*\)".*:\1:;s:%s::;p}'` ; do \
		sed -n '/'$$s'[^ ]* =/{s:.* \([^ ]*'$$s'[^ ]*\) .*:extern char \1[] __attribute__((weak)); if (!strcmp(sym, "\1")) return \1;:;p}' $$files ; \
	done > $@

endif
