include ../Common.mk

SOBJS := portfw.so mfw.so autofw.so user.so

%_sh.o : %.c
	$(CC) $(SH_CFLAGS) -o $@ -c $<

%.so : %_sh.o $(OBJS)
	$(CC) -shared -o $@ $(SH_LDFLAGS) $(OBJS) $< $(SH_LDLIBS)

.PRECIOUS: %.o %_sh.o

all : $(SOBJS)

clean:
	rm -f *.so *.o

