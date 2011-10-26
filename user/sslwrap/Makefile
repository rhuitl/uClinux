ifndef CONFIG_USER_SSLWRAP_SSLWRAP
# Not running under the uClinux build environment,
# so build a host version for debugging.
LDLIBS += -lssl
endif

EXEC = sslwrap
OBJS = s_server.o s_socket.o s_cb.o

CFLAGS += -DFLAT_INC
LIBS += $(LIBSSL) $(LIBCRYPTO)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
