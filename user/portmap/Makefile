# @(#) Makefile 1.5 96/05/31 15:50:40

####################################
### Beginning of configurable stuff.

# By default, logfile entries are written to the same file as used for
# sendmail transaction logs. Change the definition of the following macro
# if you disagree. See `man 3 syslog' for examples. Some syslog versions
# do not provide this flexibility.
#
FACILITY=LOG_MAIL

# To disable host access control, comment out the following macro definition.
# Note: host access control requires the strtok() and strchr() routines.
# Host access control can also be turned off by providing no access control
# tables. The local system, since it runs the portmap daemon, is always
# treated as an authorized host.

#HOSTS_ACCESS= -DHOSTS_ACCESS

# Comment out if your RPC library does not allocate privileged ports for
# requests from processes with root privilege, or the new portmap will
# always reject requests to register/unregister services on privileged
# ports. You can find out by running "rpcinfo -p"; if all mountd and NIS
# daemons use a port >= 1024 you should probably disable the next line.

CHECK_PORT = -DCHECK_PORT

# When the portmapper cannot find any local interfaces (it will complain
# to the syslog daemon) your system probably has variable-length socket
# address structures (struct sockaddr has a sa_len component; examples:
# AIX 4.1 and 4.4BSD). Uncomment next macro definition in that case.
#
# SA_LEN = -DHAS_SA_LEN		# AIX 4.x, BSD 4.4

# With verbose logging on, HP-UX 9.x and AIX 4.1 leave zombies behind when
# SIGCHLD is not ignored. Enable next macro for a fix.
#
# ZOMBIES = -DIGNORE_SIGCHLD	# AIX 4.x, HP-UX 9.x

# Uncomment the following macro if your system does not have u_long.
#
# ULONG	=-Du_long="unsigned long"

# Later versions of the tcp wrapper (log_tcp package) come with a
# libwrap.a object library. WRAP_DIR should specify the directory with
# that library.

# WRAP_DIR= ../tcp_wrappers

# Auxiliary object files that may be missing from your C library.
#
AUX	= daemon.o # strerror.o

# NEXTSTEP is a little different. The following seems to work with NS 3.2
#
# SETPGRP	=-DUSE_SETPGRP00
# LIBS	= -m
# NSARCHS	= -arch m68k -arch i386 -arch hppa

# Auxiliary libraries that you may have to specify
#
# LIBS	= -lrpc

### End of configurable stuff.
##############################

SHELL	= /bin/sh

COPT	= -Dperror=xperror $(HOSTS_ACCESS) $(CHECK_PORT) \
	$(SYS) -DFACILITY=$(FACILITY) $(ULONG) $(ZOMBIES) $(SA_LEN)
# DAVIDM - this stuff is too hard to remove errors from
CFLAGS  := $(subst -Werror,,$(CFLAGS))
CFLAGS	+= $(COPT) -O $(NSARCHS) $(SETPGRP)
OBJECTS	= portmap.o pmap_check.o from_local.o $(AUX)

all:	portmap pmap_dump pmap_set

portmap: $(OBJECTS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJECTS) $(LIBS) $(LDLIBS)

pmap_dump: pmap_dump.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $? $(LIBS) $(LDLIBS)

pmap_set: pmap_set.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $? $(LIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_PORTMAP_PORTMAP   /bin/portmap
	$(ROMFSINST) -e CONFIG_USER_PORTMAP_PMAP_DUMP /bin/pmap_dump
	$(ROMFSINST) -e CONFIG_USER_PORTMAP_PMAP_SET  /bin/pmap_set

lint:	
	lint $(COPT) $(OBJECTS:%.o=%.c)

clean:
	rm -f *.o portmap pmap_dump pmap_set from_local core *.elf *.gdb

tidy:	clean
	chmod 755 . ; chmod -R a+r .

deps:
	@$(CC) -M $(CFLAGS) *.c | grep -v /usr/include |sed 's/\.\///'

daemon.o: daemon.c
from_local.o: from_local.c
pmap_check.o: pmap_check.c pmap_check.h Makefile
pmap_dump.o: pmap_dump.c
pmap_set.o: pmap_set.c
portmap.o: portmap.c
portmap.o: pmap_check.h
strerror.o: strerror.c
