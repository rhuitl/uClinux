# make file for gcc/PalmOS single precision library

.EXPORT_ALL_VARIABLES:

INCS= mconf.h

# Objects for double precision routines
DOBJS=	acosh.o airy.o asin.o asinh.o atan.o atanh.o bdtr.o beta.o \
	btdtr.o cbrt.o chbevl.o chdtr.o clog.o cmplx.o const.o \
	cosh.o dawsn.o drand.o ei.o ellie.o ellik.o ellpe.o ellpj.o ellpk.o \
	exp.o exp10.o exp2.o expn.o expx2.o fac.o fdtr.o \
	fresnl.o gamma.o gdtr.o hyp2f1.o hyperg.o i0.o i1.o igami.o incbet.o \
	incbi.o igam.o isnan.o iv.o j0.o j1.o jn.o jv.o k0.o k1.o kn.o kolmogorov.o \
	log.o log2.o log10.o lrand.o nbdtr.o ndtr.o ndtri.o pdtr.o planck.o \
	polevl.o polmisc.o polylog.o polyn.o pow.o powi.o psi.o rgamma.o round.o \
	shichi.o sici.o sin.o sindg.o sinh.o spence.o stdtr.o struve.o \
	tan.o tandg.o tanh.o unity.o yn.o zeta.o zetac.o \
	sqrt.o floor.o setprec.o mtherr.o

# Objects for single precision routines
FOBJS=	acoshf.o airyf.o asinf.o asinhf.o atanf.o \
	atanhf.o bdtrf.o betaf.o cbrtf.o chbevlf.o chdtrf.o \
	clogf.o cmplxf.o constf.o coshf.o dawsnf.o ellief.o \
	ellikf.o ellpef.o ellpkf.o ellpjf.o expf.o exp2f.o \
	exp10f.o expnf.o expx2f.o facf.o fdtrf.o floorf.o fresnlf.o \
	gammaf.o gdtrf.o hypergf.o hyp2f1f.o igamf.o igamif.o \
	incbetf.o incbif.o i0f.o i1f.o ivf.o j0f.o j1f.o \
	jnf.o jvf.o k0f.o k1f.o knf.o logf.o log2f.o \
	log10f.o nbdtrf.o ndtrf.o ndtrif.o pdtrf.o polynf.o \
	powif.o powf.o psif.o rgammaf.o shichif.o sicif.o \
	sindgf.o sinf.o sinhf.o spencef.o sqrtf.o stdtrf.o \
	struvef.o tandgf.o tanf.o tanhf.o ynf.o zetaf.o \
	zetacf.o polevlf.o

#
# only include this if we don't have shared libs
#
ifndef CONFIG_BINFMT_SHARED_FLAT
 # Printf and Scanf based routines
 PSRC=../libc/stdio2/printf.c
 POBJ=printf.o sprintf.o fprintf.o vprintf.o vsprintf.o vfprintf.o \
      snprintf.o vfnprintf.o
 SSRC=../libc/stdio2/scanf.c
 SOBJ=scanf.o sscanf.o fscanf.o vscanf.o vsscanf.o vfscanf.o
endif

# Other routines and the above objects
OBJS=	fmod.o modf.o $(FOBJS) $(DOBJS) $(POBJ) $(SOBJ)

CFLAGS += -g

ifeq ($(findstring uClibc, $(LIBCDIR)),uClibc)
# with uClibc this somehow dies on the m5200
CFLAGS += -O2
endif

all: libm.a

libm.a: $(OBJS) $(INCS)
	$(AR) rv libm.a $(OBJS)
	$(RANLIB) libm.a



#
# only include this if we don't have shared libs
#
ifndef CONFIG_BINFMT_SHARED_FLAT

$(POBJ): $(PSRC)
	$(CC) -I../libc/include $(CFLAGS) -DFLOATS=1 -DL_$* $< -c -o $*.o

$(SOBJ): $(SSRC)
	$(CC) -I../libc/include $(CFLAGS) -DFLOATS=1 -DL_$* $< -c -o $*.o

#strtod.o: strtod.c
#	$(CC) -I../libc/include $(CFLAGS) -DFLOATS=1 -o strtod.o -c strtod.c

#gcvt.o: gcvt.c
#	$(CC) -I../libc/include $(CFLAGS) -DFLOATS=1 -o gcvt.o -c gcvt.c
endif


romfs:

clean:
	-rm -f *.[oa] *~ core
