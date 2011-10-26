
EXEC = boa
OBJS = alias.o auth.o boa.o cgi.o cgi_header.o config.o get.o hash.o \
	globals.o \
	log.o nls.o pipe.o queue.o read.o request.o response.o signals.o \
	timestamp.o util.o

FLTFLAGS += -s 16384

EXTRALIBS = $(LIBCRYPT)

ifdef CONFIG_PROP_BOA_SECURITY_COUNT
CFLAGS += -DSECURITY_COUNTS
endif

ifdef CONFIG_USER_BOA_WITH_SSL
CFLAGS += -DSERVER_SSL=1
EXTRALIBS += $(LIBSSL) $(LIBCRYPTO)
endif

ifdef CONFIG_USER_TINYLOGIN_SHADOWPASSWDS
CFLAGS += -DSHADOW_AUTH
endif

ifdef CONFIG_USER_FLATFSD_FLATFSD
CFLAGS += -DCONFIG_USER_FLATFSD_FLATFSD=1
endif

ifdef CONFIG_PROP_AMAZON_BOA_LDAP
CFLAGS += -DLDAP_HACK
EXTRALIBS += -lldap -llber -static $(LIBSNAPGEAR) $(LIBCONFIG)
endif

ifdef CONFIG_USER_BOA_EMERG
CFLAGS += -DSYSLOGS_AT_EMERG
endif

ifdef CONFIG_USER_BOA_LOGGING
CFLAGS += -DBOA_TIME_LOG
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(EXTRALIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o


