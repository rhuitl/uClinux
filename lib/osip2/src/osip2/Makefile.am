
EXTRA_DIST = fsm.h xixt.h

lib_LTLIBRARIES = libosip2.la

libosip2_la_SOURCES =  \
ict_fsm.c      ist_fsm.c      nict_fsm.c          nist_fsm.c    \
ict.c          ist.c          nict.c              nist.c        \
fsm_misc.c     osip.c         osip_transaction.c  osip_event.c  \
port_sema.c    port_fifo.c    port_thread.c       osip_dialog.c \
osip_negotiation.c            port_condv.c        osip_time.c


libosip2_la_LDFLAGS = -version-info $(LIBOSIP_SO_VERSION) \
 $(FSM_LIB) $(EXTRA_LIB) ../osipparser2/libosipparser2.la


INCLUDES = -I$(top_srcdir)/include
AM_CFLAGS = $(SIP_CFLAGS) $(SIP_FSM_FLAGS) $(SIP_EXTRA_FLAGS)


