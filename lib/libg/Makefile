#
#	Makefile -- Master makefile for all libraries.
#

.EXPORT_ALL_VARIABLES:


# CFLAGS += -I../../libc/include
#
# Include architecture specific build rules.
#


DIRS  = gtermcap

all: $(DIRS)
	for i in $(DIRS) ; do make -C $$i || exit $? ; done

romfs:

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done

