CFLAGS += -I../../include -I.. -Itacc/include -Wall

.PHONY: tacacs
tacacs: tacacs.o
	make -C tacc/lib libtac.a

.PHONY: pppoatm
pppoatm: pppoatm.o text2atm.o text2qos.o

.PHONY: radius
radius: radius.o librad.o

.PHONY: pppoe
pppoe: libpppoe.a

libpppoe.a:
	make -f Makefile.linux -C pppoe libpppoe.a

clean:
	make -C tacc/lib clean
	make -f Makefile.linux -C pppoe clean
	-rm -f *.o
