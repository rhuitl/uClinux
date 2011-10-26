# makefile template

include MakeInclude

VLAN_OBJS = vconfig.o

ALL_OBJS = ${VLAN_OBJS}

VCONFIG = vconfig                  #program to be created


all: ${VCONFIG}


#This is pretty silly..
vconfig.h: Makefile
	touch vconfig.h


$(VCONFIG): $(VLAN_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(VLAN_OBJS) $(LDLIBS$(LDLIBS_$@))


$(ALL_OBJS): %.o: %.c %.h
	@echo " "
	@echo "Making $<"
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(VCONFIG) vconfig.h

romfs:
	$(ROMFSINST) /bin/vconfig



