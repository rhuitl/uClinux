include ../Common.mk

all : lib$(LIBMASQ).a

lib$(LIBMASQ).a: ip_masq_ioctl.o
	$(AR) rv $@ $?

clean:
	rm -f *.[oa] core
