EXEC = lpr
OBJS = lpr.o \
	../common_source/startdaemon.o \
	../common_source/common.o \
    ../common_source/common_vars.o \
	../common_source/getcap.o

all: $(EXEC)
                                                                                
$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

clean:
	-rm -f $(OBJS) $(EXEC)
