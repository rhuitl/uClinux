
EXEC1 = pptp
OBJS1 = pptp.o pptp_gre.o ppp_fcs.o pty.o pptp_ctrl.o dirutil.o \
	vector.o inststr.o version.o 

### DEPS
### pptp_callmgr.h pptp_gre.h ppp_fcs.h pty.h util.h

EXEC2 = pptp_callmgr
OBJS2 = pptp_callmgr.o pptp_ctrl.o dirutil.o vector.o \
	version.o

### DEPS
### pptp_callmgr.h pptp_ctrl.h dirutil.h pptp_msg.h vector.h
 

CFLAGS += '-DPPPD_BINARY="/bin/pppd"' '-DPPTP_LINUX_VERSION="1.0.2"'
#CFLAGS += -DPPTPDEBUG
FLTFLAGS += -s 8192

all:		$(EXEC1) $(EXEC2)

$(EXEC1):	$(OBJS1)
		$(CC) $(LDFLAGS) -o $@ $(OBJS1) $(LDLIBS) $(LIBUTIL)

$(EXEC2):	$(OBJS2)
		$(CC) $(LDFLAGS) -o $@ $(OBJS2) $(LDLIBS) $(LIBUTIL)

romfs:
	$(ROMFSINST) -e CONFIG_USER_PPTP_CLIENT_PPTP /bin/pptp
	$(ROMFSINST) -e CONFIG_USER_PPTP_CLIENT_PPTP_CALLMGR /bin/pptp_callmgr

clean:
		-rm -f $(EXEC1) $(EXEC2) *.elf *.gdb *.o

