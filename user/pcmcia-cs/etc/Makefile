#
# etc/Makefile 1.57 2000/08/22 23:30:07 (David Hinds)
#

# Include site dependent options
include ../config.mk

all:
ifeq ($(HOST_ARCH),$(ARCH))
	@set -e ; $(MAKE) -C cis
endif

dep:
clean:

install:
	@set -e ; $(MAKE) -C cis install
	@./install-etc $(PREFIX)
