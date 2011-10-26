########################################################################
# This is the makefile for NetPipe
# Simply type make with one of the following choices for environments:
#
#      mpi         : will use mpicc to compile
#      mplite      : It will look for the MP_Lite library in $HOME/mplite
#      tcp         : You start the receiver and transmitter manually
#      paragon     : Uses MPI on the Paragon
#      pvm         : Old version doesn't use pvm_spawn
#                    Use 'NPpvm -r' on receiver and 'NPpvm' on transmitter
#      tcgmsg      : Run directly on TCGMSG
#      tcgmsg-mpich: Test TCGMSG layer on top of mpich
#      lapi        : Test the LAPI interface on the IBM SP
#      gm          : Directly measure raw GM on Myrinet
#                    Use 'NPgm -r' on receiver and 'NPgm -t -h ...' on trans
#      shmem       : Directly measure SHMEM on Cray and SGI systems
#      gpshmem     : Measure GPSHMEM on any other system using shmem.c
#
#      For more information, see the function printusage() in netpipe.c
#
########################################################################

#CC         = cc
#CFLAGS     = -O
SRC        = ./src

# For MPI, mpicc will set up the proper include and library paths

MPICC       = mpicc

MP_Lite_home   = $(HOME)/MP_Lite

PVM_HOME   = /usr/share/pvm3
PVM_ARCH   = LINUX
#PVM_ARCH   = LINUXALPHA

TCGMSG_HOME = $(HOME)/np/packs/ga
TCGMSG_LIB = $(TCGMSG_HOME)/lib/LINUX/libtcgmsg.a
TCGMSG_INC = $(TCGMSG_HOME)/include

TCGMSG_MPI_HOME= $(HOME)/np/ga
TCGMSG_MPI_LIB = $(TCGMSG_MPI_HOME)/lib/LINUX/libtcgmsg-mpi.a
TCGMSG_ARMCI_LIB = $(TCGMSG_MPI_HOME)/armci-1.0/lib/LINUX/libarmci.a
TCGMSG_MPI_INC = $(TCGMSG_MPI_HOME)/include

GM_HOME = /opt/gm
GM_INC = $(GM_HOME)/include
GM_LIB = -L $(GM_HOME)/lib -lgm
GM_DRI = $(GM_HOME)/drivers/linux/gm

GPSHMEM_LIB = $(HOME)/np/ga/gpshmem/lib/libgpshmem.a
GPSHMEM_INC = $(HOME)/np/ga/gpshmem/include

ARMCI_LIB   = $(HOME)/armci/lib/LINUX/libarmci.a -lm
ARMCI_INC   = $(HOME)/armci/src

# MTHOME should be defined in the environment
#MTHOME=/usr/mellanox
VAPI_INC    = $(MTHOME)/include
VAPI_LIB    = $(MTHOME)/lib

# If the MPI-2 implementation provides the mpicc compiler, then simply
# set MPI2CC to mpicc, and set MPI2_LIB and MPI2_INC to nothing.
# If mpicc is not included with the implementation, then set MPI2CC to
# an appropriate compiler, and set the paths to the MPI-2 library and include
# directory (library path should be absolute, e.g. MPI2_LIB = 
# $(HOME)/mpi/libmpi.a)

MPI2CC   = mpicc
MPI2_LIB =
MPI2_INC =

all:tcp 

clean:
	rm -f *.o NP* np.out

#
# This section of the Makefile is for compiling the binaries
#


tcp: $(SRC)/tcp.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) $(SRC)/netpipe.c $(SRC)/tcp.c -DTCP  -o NPtcp -I$(SRC)

memcpy: $(SRC)/memcpy.c $(SRC)/netpipe.c $(SRC)/netpipe.h
	$(CC) $(CFLAGS) $(SRC)/netpipe.c $(SRC)/memcpy.c \
              -DMEMCPY -o NPmemcpy -I$(SRC)

MP_memcpy: $(SRC)/memcpy.c $(SRC)/netpipe.c $(SRC)/netpipe.h $(SRC)/MP_memcpy.c
	$(CC) $(CFLAGS) -mmmx -msse $(SRC)/netpipe.c $(SRC)/memcpy.c \
              $(SRC)/MP_memcpy.c -DMEMCPY -DUSE_MP_MEMCPY -o NPmemcpy -I$(SRC)

disk: $(SRC)/disk.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) $(SRC)/netpipe.c $(SRC)/disk.c -DDISK -o NPdisk -I$(SRC)

sync: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	( cd ~/mplite; make clean; make sync; )
	$(CC) $(CFLAGS) -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c -o NPmplite \
         -I$(SRC) -I$(MP_Lite_home) $(MP_Lite_home)/libmplite.a

debug2: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	( cd ~/mplite; make debug2; )
	$(CC) $(CFLAGS) -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c -o NPmplite \
         -I$(SRC) -I$(MP_Lite_home) $(MP_Lite_home)/libmplite.a

mpi: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(MPICC) $(CFLAGS) -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c -o NPmpi -I$(SRC)
	@ rm -f netpipe.o mpi.o

mpipro: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mpicc $(CFLAGS) -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c \
            -o NPmpipro -I$(SRC)
	@ rm -f netpipe.o mpi.o

mpipro-gm: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	cc -O -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c \
            /usr/lib/libmpipro_tg_i386.a \
            -o NPmpipro-gm -I./src -I/usr/include \
            -L $HOME/np/packs/gm/binary/lib -lgm -lm -lpthread

mpich: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mpichcc $(CFLAGS) -DMPI $(SRC)/netpipe.c \
            $(SRC)/mpi.c -o NPmpich -I$(SRC)
	@ rm -f netpipe.o mpi.o

mpich-trace: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mpichcc $(CFLAGS) -mpitrace -DMPI $(SRC)/netpipe.c \
            $(SRC)/mpi.c -o NPmpich -I$(SRC)
	@ rm -f netpipe.o mpi.o

mpich-log: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h  
	mpichcc $(CFLAGS) -mpilog -DMPI $(SRC)/netpipe.c \
            $(SRC)/mpi.c -o NPmpich -I$(SRC)
	@ rm -f netpipe.o mpi.o

mpich-gm: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mpichgmcc $(CFLAGS) -DMPI $(SRC)/netpipe.c \
            $(SRC)/mpi.c -o NPmpich-gm -I$(SRC)
	@ rm -f netpipe.o mpi.o

gm: $(SRC)/gm.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) -DGM $(SRC)/netpipe.c $(SRC)/gm.c \
            -o NPgm -I$(SRC) -I$(GM_INC) -I$(GM_DRI) \
            $(GM_LIB) -static

mvich: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mvichcc $(CFLAGS) -DMPI $(SRC)/netpipe.c \
            $(SRC)/mpi.c -o NPmvich -I$(SRC) -lvipl
	@ rm -f netpipe.o mpi.o

mvich-gn: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mvichcc $(CFLAGS) -DMPI $(SRC)/netpipe.c \
            $(SRC)/mpi.c -o NPmvich-gn -I$(SRC) -lgnivipl
	@ rm -f netpipe.o mpi.o

mplite MP_Lite sigio: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	( cd $(MP_Lite_home); make; )
	$(CC) $(CFLAGS) -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c \
            -o NPmplite -I$(SRC) -I$(MP_Lite_home) $(MP_Lite_home)/libmplite.a

mplite-mvia: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	( cd ~/mplite; make mvia; )
	$(CC) $(CFLAGS) -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c \
             -o NPmplite-mvia -I$(SRC) -I$(MP_Lite_home) \
             $(MP_Lite_home)/libmplite.a -lvipl -lpthread

mplite-gn: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	( cd ~/mplite; make giganet; )
	$(CC) $(CFLAGS) -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c \
            -o NPmplite-gn -I$(SRC) -I$(MP_Lite_home) \
            $(MP_Lite_home)/libmplite.a -lgnivipl -lpthread

mplite-ib: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	( cd $(MP_Lite_home); make ib; )
	$(CC) $(CFLAGS) -g -DMPI $(SRC)/netpipe.c $(SRC)/mpi.c \
            -o NPmplite-ib -I$(SRC) -I$(MP_Lite_home) \
            $(MP_Lite_home)/libmplite.a -L/usr/mellanox/lib \
            -lmpga -lvapi -lpthread

pvm: $(SRC)/pvm.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) -DPVM $(SRC)/netpipe.c $(SRC)/pvm.c \
           -o NPpvm -I$(SRC) -I$(PVM_HOME)/include \
           -L $(PVM_HOME)/lib/$(PVM_ARCH)/ -lpvm3 -lgpvm3

tcgmsg: $(SRC)/tcgmsg.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) -DTCGMSG $(SRC)/netpipe.c \
           $(SRC)/tcgmsg.c -o NPtcgmsg -I$(SRC) -I$(TCGMSG_INC) $(TCGMSG_LIB) 

tcgmsg-mpich: $(SRC)/tcgmsg.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mpichcc $(CFLAGS) -DTCGMSG $(SRC)/netpipe.c \
           $(SRC)/tcgmsg.c -o NPtcgmsg.mpich -I$(SRC) -I$(TCGMSG_MPI_INC) \
           $(TCGMSG_MPI_LIB) $(TCGMSG_ARMCI_LIB)

lapi: $(SRC)/lapi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mpcc_r $(CFLAGS) -DLAPI $(SRC)/netpipe.c \
           $(SRC)/lapi.c -o NPlapi

t3e: $(SRC)/shmem.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) -DSHMEM $(SRC)/netpipe.c \
           $(SRC)/shmem.c -o NPshmem

shmem: $(SRC)/shmem.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) -DSHMEM $(SRC)/netpipe.c \
           $(SRC)/shmem.c -o NPshmem -lsma

gpshmem: $(SRC)/gpshmem.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	mpichcc $(CFLAGS) -DGPSHMEM -DSHMEM $(SRC)/netpipe.c \
           $(SRC)/gpshmem.c -I$(GPSHMEM_INC) -o NPgpshmem $(GPSHMEM_LIB) \
           $(ARMCI_LIB)
	@ rm -f netpipe.o gpshmem.o

paragon: $(SRC)/mpi.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) -nx $(CFLAGS) -DMPI $(SRC)/netpipe.c \
           $(SRC)/mpi.c -o NPparagon -I$(SRC) -lmpi
	@ echo "On the Paragon, the buffer alignment does not work."
	@ echo "Run using NPparagon -A 0."

armci: $(SRC)/armci.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(MPICC) $(CFLAGS) -DARMCI $(SRC)/netpipe.c \
           $(SRC)/armci.c -o NParmci -I$(ARMCI_INC) $(ARMCI_LIB) 

mpi2: $(SRC)/mpi2.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(MPI2CC) $(CFLAGS) -DMPI -DMPI2 $(SRC)/netpipe.c \
           $(SRC)/mpi2.c -o NPmpi2 -I$(MPI2_INC) $(MPI2_LIB)

ib: $(SRC)/ib.c $(SRC)/netpipe.c $(SRC)/netpipe.h 
	$(CC) $(CFLAGS) $(SRC)/ib.c $(SRC)/netpipe.c -o NPib \
        -DINFINIBAND -DTCP -I $(VAPI_INC) -L $(VAPI_LIB) \
        -lmpga -lvapi -lpthread

atoll: $(SRC)/atoll.c $(SRC)/netpipe.c $(SRC)/netpipe.h
	$(CC) $(CFLAGS) -DATOLL $(SRC)/netpipe.c \
        $(SRC)/atoll.c -o NPatoll \
        -I$(PALMS_PATH)/include -L$(PALMS_PATH)/lib -latoll

romfs:
	$(ROMFSINST) /bin/NPtcp

perms: all
