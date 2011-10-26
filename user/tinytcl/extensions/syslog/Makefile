CFLAGS += -I$(TCLDIR)

OBJS=syslog.o

ifndef CONFIG_LIB_TINYTCL_STATIC
CFLAGS += -fpic
SH_LDFLAGS += -L$(TCLDIR)

syslog.so: $(OBJS)
	$(CC) -shared $(SH_LDFLAGS) -o $@ $(OBJS) -ltcl $(SH_LDLIBS)

else
all: $(OBJS)
	cp $(OBJS) ..
endif

clean:
	rm -f *.o *.so

romfs:
	@-mkdir -p $(ROMFSDIR)/lib/tcl
	$(ROMFSINST) /lib/tcl/syslog.so
