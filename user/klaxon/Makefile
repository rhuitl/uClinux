# This makefile builds 2 executables. One with IDENT support, (RFC931)
# and one without. Rename the one you want to klaxon and install it as
# usual.
# mine.c is included if you wish to statically link this program
# on Solaris2.X machines, just cc -c it and then link it with
# the executable

# - known to compile cleanly on linux 1.2.13 kernel of slackware 3.0

# Change the line below if you don't like the 3 second timeout
# For finding out IDENT information
TIMEOUT=-DRFC931_TIMEOUT=3

# Uncomment the below lines for RPC rexd support only on Solaris2.X
# CFLAGS = -DRPC
# LDFLAGS = -lrpcsvc

EXEC = klaxon
OBJS = klaxon.o

# Stuff to add for rfc931 support
ifeq ($(CONFIG_USER_KLAXON_RFC931),y)
OBJS += rfc931.o
CFLAGS += $(TIMEOUT)
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	-rm -f $(EXEC) *.gdb *.o

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) -e CONFIG_USER_KLAXON_CHARGEN \
			-a "chargen stream tcp nowait root /bin/klaxon tcp-chargen" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_CHARGEN \
			-a "chargen stream udp wait   root /bin/klaxon udp-chargen" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_DISCARD \
			-a "discard stream tcp nowait root /bin/klaxon tcp-discard" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_DISCARD \
			-a "discard stream udp wait   root /bin/klaxon udp-discard" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_ECHO \
			-a "echo    stream tcp nowait root /bin/klaxon tcp-echo" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_ECHO \
			-a "echo    stream udp wait   root /bin/klaxon udp-echo" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_FTP \
			-a "ftp     stream tcp nowait root /bin/klaxon ftp" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_FTP \
			-a "ftpdata stream tcp nowait root /bin/klaxon ftp-data" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_HTTP \
			-a "http    stream tcp nowait root /bin/klaxon http" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_SMTP \
			-a "smtp    stream tcp nowait root /bin/klaxon smtp" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_SNMP \
			-a "snmp    stream tcp nowait root /bin/klaxon tcp-snmp" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_SNMP \
			-a "snmp    stream udp wait   root /bin/klaxon udp-snmp" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_SSH \
			-a "ssh     stream tcp nowait root /bin/klaxon ssh" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_TELNET \
			-a "telnet  stream tcp nowait root /bin/klaxon telnet" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_KLAXON_TFTP \
			-a "tftp    stream udp wait   root /bin/klaxon tftp" /etc/inetd.conf
