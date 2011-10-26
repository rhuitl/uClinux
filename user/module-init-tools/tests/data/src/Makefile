#! /usr/bin/make

SOURCES:=$(wildcard *.c)

X=)
BITNESS:=$(shell case `uname -m` in alpha|*64$(X) echo 64;; *$(X) echo 32;; esac)
ENDIANNESS:=$(shell case `uname -m` in alpha|*86*|ia64$(X) echo le;; *$(X) echo be;; esac)
CC=gcc

install: all
	for f in *loop*.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/loop/; done
	for f in *map*.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/map/; done
	for f in *unknown*.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/unknown/; done
	for f in *complex*.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/complex/; done
	for f in *rename*.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/rename/; done
	for f in *alias*.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/alias/; done
	for f in *modinfo*.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/modinfo/; done
	for f in *.ko; do mv $$f ../$(BITNESS)-$(ENDIANNESS)/normal/; done

all: clean $(SOURCES:.c=-$(BITNESS).ko)

clean:
	find . ../$(BITNESS)-$(ENDIANNESS) -name '*.ko' | xargs -r rm

# Other machines
MACHINES+=fandango2 #ppc64
MACHINES+=fuego # ppc
MACHINES+=opteron # x86-64

#superego_CCPREFIX=/usr/local/ppc64/bin/powerpc64-linux-
fandango2_CFLAGS=-m64

build: install 
	DIR=$$(dirname $$(pwd) ); $(foreach mach,$(MACHINES),rsync -az --delete $$DIR/ $(mach):mod-init-tools-data/ && echo $(mach) && ssh $(mach) make -C mod-init-tools-data/src CFLAGS=$($(mach)_CFLAGS) install && rsync -avz --delete $(mach):mod-init-tools-data/ $$DIR/ &&) true

%-$(BITNESS).ko: %.c
	$(CCPREFIX)$(CC) $(CFLAGS) -s -DBITS_PER_LONG=$(BITNESS) -c $< -o $@
