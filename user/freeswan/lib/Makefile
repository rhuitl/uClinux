
OBJS=addrtoa.o addrtot.o addrtypeof.o anyaddr.o atoaddr.o \
	atoasr.o atosa.o atosubnet.o atoul.o copyright.o datatot.o \
	goodmask.o initaddr.o initsaid.o initsubnet.o keyblobtoid.o\
	optionsfrom.o pfkey_v2_build.o pfkey_v2_ext_bits.o pfkey_v2_parse.o \
	pfkey_v2_debug.o \
	portof.o rangetoa.o rangetosubnet.o sameaddr.o \
	satoa.o satot.o subnetof.o subnettoa.o subnettot.o \
	subnettypeof.o ttoaddr.o ttodata.o \
	ttosa.o ttosubnet.o ttoul.o ultoa.o ultot.o ttoprotoport.o version.o 
LIB=libfreeswan.a 

CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
#CFLAGS+= -Wpointer-arith
#CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes $(USERCOMPILE)
#CFLAGS+= -pedantic
#CFLAGS+= -O3
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
#CFLAGS+= -Wbad-function-cast 

CFLAGS += -I$(ROOTDIR)/freeswan/lib
CFLAGS += -I$(ROOTDIR)/freeswan/libdes
CFLAGS += -I$(ROOTDIR)/lib/libgmp

vpath %.c $(ROOTDIR)/freeswan/lib

ARFLAGS=crvs

all: $(LIB)

$(LIB):	$(OBJS)
	ar $(ARFLAGS) $(LIB) $(OBJS)
	$(RANLIB) $(LIB)

$(OBJS): $(HDRS)

version.c:	version.in.c $(ROOTDIR)/freeswan/Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' $< >$@

romfs:

clean:
	rm -f $(LIB) *.o try* core *.core

