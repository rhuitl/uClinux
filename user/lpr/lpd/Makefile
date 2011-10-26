EXEC = lpd
OBJS = rcmd.o lpd.o printjob.o recvjob.o \
	../common_source/displayq.o \
	../common_source/rmjob.o \
	../common_source/startdaemon.o \
	lpdchar.o \
	../common_source/common.o \
	key.o modes.o \
	../common_source/common_vars.o \
	../common_source/getcap.o \
	../common_source/vis.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

clean:
	-rm -f $(OBJS) $(EXEC)
