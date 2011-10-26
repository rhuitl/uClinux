#
# etc/cis/Makefile $Version$ 2000/04/29 02:00:58 (David Hinds)
#

# Include site dependent options
include ../../config.mk

ETC = $(PREFIX)/etc/pcmcia
PACK = ../../debug-tools/pack_cis

CIS = $(patsubst %.cis,%.dat,$(wildcard *.cis))

all: $(CIS)

dep:

clean:
	rm -f *.dat

install: $(CIS)
	@mkdir -p $(ETC)/cis
	cp *.dat $(ETC)/cis

.SUFFIXES: .dat .cis
.cis.dat:
	$(PACK) -o $@ $<
