TARGETS=lib/libccmalloc.a  obj/ccmalloc-g++.o  obj/ccmalloc-gcc.o bin/ccmalloc

#--------------------------------------------------------------------------#

OBJ=obj/callchain.o obj/hash.o obj/wrapper.o
ifeq ($(USE_DYNAMIC_LINKING),)
OBJ += obj/myalloc.o
PREFIX=$(ROOTDIR)/lib/libccmalloc
COMPILERS=gcc g++
endif

#--------------------------------------------------------------------------#

all: $(TARGETS)

#test.S: test.c
#	$(CC) $(CFLAGS) -S -g0 -O0 -fno-omit-frame-pointer -o $@ test.c

clean:
	-rm -f obj/*.o lib/*.a bin/* core

distclean: clean
	rm -f src/config.h Makefile
	rm -rf obj lib bin
	cd test; make clean

#--------------------------------------------------------------------------#
# The library is not inialized statically.  Thus the library may produce
# some bogus messages like `free(...) called after reporting'.  However it
# should work even if another compiler is used by the user.
#
lib/libccmalloc.a: $(OBJ)
	ar rc $@ $(OBJ)
	ranlib $@

#--------------------------------------------------------------------------#

obj/callchain.o: src/config.h src/hash.h src/callchain.c src/ccmalloc.h
	$(CC) $(CFLAGS) -c -o $@ src/callchain.c
obj/hash.o: src/hash.h src/hash.c
	$(CC) $(CFLAGS) -c -o $@ src/hash.c
obj/wrapper.o: src/config.h src/wrapper.c
	$(CC) $(CFLAGS) -c -o $@ src/wrapper.c
obj/myalloc.o: src/config.h src/myalloc.c
	$(CC) $(CFLAGS) -c -o $@ src/myalloc.c
bin/ccmalloc: Makefile src/ccmalloc.in
	rm -f $@
	sed \
	-e 's,@''PREFIX@,$(PREFIX),g' \
	-e 's,@''COMPILERS@,"$(COMPILERS)",g' \
	-e 's,@''VERSION@,0.3.9,g' \
	src/ccmalloc.in > $@
	chmod 755 $@

#--------------------------------------------------------------------------#

.PHONY: all clean distclean install

#-------------------------------------------------------------------------#
# automatically generated goals for C++ static initializers
#
obj/ccmalloc-g++.o: src/ccmalloc.cc src/config.h src/ccmalloc.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -DCTORDTOR -g -c -o $@ src/ccmalloc.cc
	cp $@ lib

obj/ccmalloc-gcc.o: src/ccmalloc.cc src/config.h src/ccmalloc.h
	$(CC) $(CFLAGS) -DCTORDTOR -g -c -o $@ src/ccmalloc.cc
	cp $@ lib

#-------------------------------------------------------------------------#

install: all
	./util/install bin/ccmalloc $(PREFIX)/bin
	./util/install lib/libccmalloc.a $(PREFIX)/lib
	./util/install ccmalloc.cfg $(PREFIX)/share/ccmalloc
	./util/install obj/ccmalloc-g++.o $(PREFIX)/lib
	./util/install obj/ccmalloc-gcc.o $(PREFIX)/lib

romfs:

image:
