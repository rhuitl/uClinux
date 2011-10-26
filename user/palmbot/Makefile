
EXEC = palmbot
OBJS = palmbot.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CXX) $(LDFLAGS) -m5307 -o $@ $(OBJS) $(LIBM) $(CXXLIBS)

.cpp.o:
	$(CXX) $(CXXFLAGS) -m5307 -c $<

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

