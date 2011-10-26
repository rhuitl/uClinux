#
# build a Palm app that can be downloaded to run uClinux
#

APP = uClinuxPalm
ICONTEXT = "Palm Loader"
APPID = pFld
IMAGE = $(IMAGEDIR)/image.bin
OBJS = PalmLoader.o

PALMOSCC = m68k-palmos-coff-gcc

# uncomment this if you want to build a gdb debuggable version
# DEFINES = -DDEBUG
# -Dint=long

INCLUDES =  

CSFLAGS = -O2 -static -S $(DEFINES) $(INCLUDES)
CFLAGS =  -O2 -static  $(DEFINES) $(INCLUDES)

LIBS = 

PILRC = pilrc
TXT2BITM = txt2bitm
OBJRES = m68k-palmos-coff-obj-res
BUILDPRC = build-prc

PRC = $(IMAGEDIR)/$(APP).prc

all: $(PRC)

.S.o:
	$(PALMOSCC) $(TARGETFLAGS) -c $<

.c.s:
	$(PALMOSCC) $(CSFLAGS) $<

.c.o:
	$(PALMOSCC) -c $(CFLAGS) $<

$(PRC): code.stamp bin.stamp page0000.bin
	$(BUILDPRC) $@ $(ICONTEXT) $(APPID) *.grc *.bin

code.stamp: $(APP)
	$(OBJRES) $(APP)
	touch code.stamp

bin.stamp: PalmLoader.rcp
	$(PILRC) PalmLoader.rcp
	touch bin.stamp

$(APP): $(OBJS)
	$(PALMOSCC) $(CFLAGS) $(OBJS) $(LIBS) -o $@

download:
	PILOTRATE=57600 pilot-xfer -p /dev/ttyS1 -i $(PRC)

page0000.bin: $(IMAGE)
	rm -f page????.bin
	split -b 4096 $(IMAGE) page
	c=0; for i in page* ; do mv $$i page`printf %.4x $$c`.bin ; c=`expr $$c + 1`; done

clean:
	rm -rf *.[oa] $(APP) *.bin *.stamp *.[pg]rc

