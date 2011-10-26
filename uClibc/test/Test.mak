# Common makefile rules for tests
#
# Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
#
# Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.

ifeq ($(TESTS),)
TESTS := $(patsubst %.c,%,$(wildcard *.c))
endif
ifneq ($(TESTS_DISABLED),)
TESTS := $(filter-out $(TESTS_DISABLED),$(TESTS))
endif
ifeq ($(SHELL_TESTS),)
SHELL_TESTS := $(patsubst %.sh,shell_%,$(wildcard *.sh))
endif

ifneq ($(filter-out test,$(TESTS)),$(TESTS))
$(error Sanity check: cannot have a test named "test.c")
endif

top_builddir = ../../
include ../Rules.mak

U_TARGETS := $(TESTS)
G_TARGETS := $(patsubst %,%_glibc,$(U_TARGETS))

ifeq ($(GLIBC_ONLY),)
TARGETS   += $(U_TARGETS)
endif
ifeq ($(UCLIBC_ONLY),)
TARGETS   += $(G_TARGETS)
endif
CLEAN_TARGETS := $(U_TARGETS) $(G_TARGETS)
COMPILE_TARGETS :=  $(TARGETS)
TARGETS += $(SHELL_TESTS)
RUN_TARGETS := $(patsubst %,%.exe,$(TARGETS))

define binary_name
$(patsubst %.exe,%,$@)
endef

define diff_test
	$(Q)\
	for x in "$(binary_name).out" "$(patsubst %_glibc,%,$(binary_name)).out" ; do \
		test -e "$$x.good" && $(do_showdiff) "$(binary_name).out" "$$x.good" && exec diff -u "$(binary_name).out" "$$x.good" ; \
	done ; \
	true
endef
define uclibc_glibc_diff_test
	$(Q)\
	test -z "$(DODIFF_$(patsubst %_glibc,%,$(binary_name)))" && exec true ; \
	uclibc_out="$(binary_name).out" ; \
	glibc_out="$(patsubst %_glibc,%,$(binary_name)).out" ; \
	$(do_showdiff) $$uclibc_out $$glibc_out ; \
	exec diff -u "$$uclibc_out" "$$glibc_out"
endef
define exec_test
	$(showtest)
	$(Q)\
	$(WRAPPER) $(WRAPPER_$(patsubst %_glibc,%,$(binary_name))) \
	./$(binary_name) $(OPTS) $(OPTS_$(patsubst %_glibc,%,$(binary_name))) &> "$(binary_name).out" ; \
		ret=$$? ; \
		expected_ret="$(RET_$(patsubst %_glibc,%,$(binary_name)))" ; \
		test -z "$$expected_ret" && export expected_ret=0 ; \
	if ! test $$ret -eq $$expected_ret ; then \
		$(RM) $(binary_name) ; \
		echo "ret == $$ret ; expected_ret == $$expected_ret" ; \
		cat "$(binary_name).out" ; \
		exit 1 ; \
	fi
	$(SCAT) "$(binary_name).out"
endef

test check all: run
run: $(RUN_TARGETS) compile
$(RUN_TARGETS): $(TARGETS)
ifeq ($(shell echo "$(SHELL_TESTS)"|grep "$(binary_name)"),)
	$(exec_test)
	$(diff_test)
ifeq ($(UCLIBC_ONLY),)
	$(uclibc_glibc_diff_test)
endif
endif

compile: $(COMPILE_TARGETS)

G_TARGET_SRCS := $(patsubst %,%.c,$(G_TARGETS))
U_TARGET_SRCS := $(patsubst %,%.c,$(U_TARGETS))

$(MAKE_SRCS): Makefile $(TESTDIR)Makefile $(TESTDIR)Rules.mak $(TESTDIR)Test.mak

$(U_TARGETS): $(U_TARGET_SRCS) $(MAKE_SRCS)
	$(showlink)
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS_$@) -c $@.c -o $@.o
	$(Q)$(CC) $(LDFLAGS) $@.o -o $@ $(EXTRA_LDFLAGS) $(LDFLAGS_$@)

$(G_TARGETS): $(U_TARGET_SRCS) $(MAKE_SRCS)
	$(showlink)
	$(Q)$(HOSTCC) $(HOST_CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS_$(patsubst %_glibc,%,$@)) -c $(patsubst %_glibc,%,$@).c -o $@.o
	$(Q)$(HOSTCC) $(HOST_LDFLAGS) $@.o -o $@ $(EXTRA_LDFLAGS) $(LDFLAGS_$(patsubst %_glibc,%,$@))


shell_%:
	$(showtest)
	$(Q)$(SHELL) $(patsubst shell_%,%.sh,$(binary_name))

%.so: %.c
	$(showlink)
	$(Q)$(CC) \
		$(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS_$(patsubst %_glibc,%,$@)) \
		-fPIC -shared $< -o $@ -Wl,-soname,$@ \
		$(LDFLAGS) $(EXTRA_LIBS) $(LDFLAGS_$(patsubst %_glibc,%,$@))

clean:
	$(showclean)
	$(Q)$(RM) *.a *.o *.so *~ core *.out *.gdb $(CLEAN_TARGETS) $(EXTRA_CLEAN)

.PHONY: all check clean test run compile
