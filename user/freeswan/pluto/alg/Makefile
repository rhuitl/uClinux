.EXPORT_ALL_VARIABLES:

EXTRA_CFLAGS += -I$(ROOTDIR)/freeswan -I$(ROOTDIR)/freeswan/lib \
			-I$(ROOTDIR)/freeswan/pluto \
			-I$(ROOTDIR)/freeswan/pluto/alg \
			-I$(ROOTDIR)/freeswan/libcrypto \
			-I$(ROOTDIR)/freeswan/libdes

vpath %.h $(ROOTDIR)/freeswan/pluto/alg
vpath %.c $(ROOTDIR)/freeswan/pluto/alg

# special hack required because of exported object files
# %.c: $(ROOTDIR)/freeswan/pluto/%.c
#	ln -fs $< $@

include $(ROOTDIR)/freeswan/pluto/alg/Makefile

