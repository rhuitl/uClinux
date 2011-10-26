EXE1 = cxx_iostream

CCOBJS1=iostream.o
CCSRC1=iostream.cxx

CXXFLAGS += -I$(STL_INCDIR)
CXX_LDFLAGS += -L$(STL_LIBDIR)

all: $(EXE1)

$(EXE1): $(CCOBJS1)
	$(CXX) $(CXX_LDFLAGS) -o $@ $(CCOBJS1) $(LIBM) $(CXXLIBS)

$(CCOBJS1): $(CCSRC1)
	$(CXX) -c $(CXXFLAGS) -o $@ $(CCSRC1)

romfs:
	$(ROMFSINST)  /bin/$(EXE1)

clean:
	rm -f *.o $(EXE1) *.gdb


