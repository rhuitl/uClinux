EXEC = lpq
OBJS =  lpq.o \
	../common_source/displayq.o \
	../common_source/common.o \
    ../common_source/common_vars.o \
	../common_source/getcap.o \
	../common_source/vis.o

all: $(EXEC)
                                                                                
$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

clean:
	-rm -f $(OBJS) $(EXEC)
