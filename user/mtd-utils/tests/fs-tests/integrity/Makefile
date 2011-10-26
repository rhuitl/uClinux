
ifeq ($(origin CC),default)
CC = gcc
endif

CFLAGS := $(CFLAGS) -Wall -g -O2 -I../lib

LDFLAGS := $(LDFLAGS)

TARGETS = integck

all: $(TARGETS)

$(TARGETS): ../lib/tests.o

../lib/tests.o: ../lib/tests.h

clean:
	rm -f *.o $(TARGETS)

tests: all
	./integck
