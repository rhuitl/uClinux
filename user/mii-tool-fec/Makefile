#
# path to the net-lib support library. Default: lib
# NET_LIB_PATH = lib

PROGS = mii-tool-fec

# -include config.make

# Compiler and Linker Options
COPTS = -D_GNU_SOURCE -D__USE_BSD

# NET_LIB = $(NET_LIB_PATH)/lib$(NET_LIB_NAME).a
# CFLAGS	+= $(COPTS) -I. -idirafter ./include/ -I$(NET_LIB_PATH)
# LDFLAGS	+= $(LOPTS) -L$(NET_LIB_PATH)

# NLIB	= -l$(NET_LIB_NAME)

# MDEFINES = COPTS='$(COPTS)' LOPTS='$(LOPTS)' TOPDIR='$(TOPDIR)'

%.o:		%.c config.h version.h intl.h net-features.h $<
		$(CC) $(CFLAGS) -c $<

all:	mii-tool-fec

GDBPROGS := $(PROGS:%=%.gdb)

clean:
	rm -f mii-tool-fec  mii-tool-fec.o  mii-tool-fec.gdb

distclean: 	clean


# libdir:
# 		@$(MAKE) -C $(NET_LIB_PATH) $(MDEFINES)

romfs:
	$(ROMFSINST) -e CONFIG_USER_NET_TOOLS_MII_TOOL_FEC /bin/mii-tool-fec

