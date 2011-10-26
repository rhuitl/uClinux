OBJS = ap0.o aps.o asl.o asn.o asx.o avl.o host.o mis.o miv0.o miv1.o miv2.o miv3.o miv4.o miv5.o miv6.o miv7.o mix.o oid.o rdx.o smp.o smx.o tcp.o udp.o vec.o

LIBRARY = libsnmplib.a

all: $(LIBRARY)

test:

romfs:

$(LIBRARY): $(OBJS)
	$(AR) rcv $@ $(OBJS)
	-$(RANLIB) $@

clean::
	$(RM) $(OBJS) $(LIBRARY)
