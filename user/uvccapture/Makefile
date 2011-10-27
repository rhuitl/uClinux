#CC=gcc
#CPP=g++
APP_BINARY=uvccapture
VERSION = 0.4
PREFIX=/usr/local/bin

WARNINGS = -Wall


CFLAGS += -std=gnu99 -O2 -DLINUX -DVERSION=\"$(VERSION)\" $(WARNINGS)
CPPFLAGS = $(CFLAGS)

OBJECTS= uvccapture.o v4l2uvc.o

all:    uvccapture

clean:
	@echo "Cleaning up directory."
	rm -f *.a *.o $(APP_BINARY) core *~ log errlog

install:
	install $(APP_BINARY) $(PREFIX)

# Applications:
uvccapture: $(OBJECTS)
	$(CC)   $(OBJECTS)  $(LDFLAGS) -lm -ljpeg -o $(APP_BINARY)

romfs:
	$(ROMFSINST) /bin/$(APP_BINARY)
