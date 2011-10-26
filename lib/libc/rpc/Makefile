#
#	Makefile -- makefile for rpc library.
#

LIBC = ../libc.a

OBJS = auth_none.o auth_unix.o authunix_prot.o \
	bindresvport.o clnt_generic.o clnt_perror.o \
	clnt_raw.o clnt_simple.o clnt_tcp.o clnt_udp.o \
	get_myaddress.o getrpcent.o getrpcport.o pmap_clnt.o \
	pmap_getmaps.o pmap_getport.o pmap_prot.o pmap_prot2.o \
	pmap_rmt.o rpc_callmsg.o rpc_commondata.o \
	rpc_dtablesize.o rpc_prot.o sa_len.o svc.o svc_auth.o \
	svc_auth_unix.o svc_raw.o svc_run.o svc_simple.o \
	svc_tcp.o svc_udp.o xdr.o xdr_array.o xdr_float.o \
	xdr_mem.o xdr_rec.o xdr_reference.o xdr_stdio.o


all: $(LIBC)

$(LIBC): $(LIBC)($(OBJS))

clean::
	-rm *.a *.o


