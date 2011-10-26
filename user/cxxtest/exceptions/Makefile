EXE1 = cxx_exception
EXE2 = cxx_except

CCOBJS1=exception.o
CCSRC1=exception.cpp

CCOBJS2=except.o
CCSRC2=except.cpp

# We need to remove the -g option from CXXFLAGS otherwise exceptions don't work

CXXFLAGS:=$(CXXFLAGS:-g=)
CXX_LDFLAGS:=$(CXX_LDFLAGS:-g=)

CXXFLAGS += -I$(STL_INCDIR)
CXX_LDFLAGS += -L$(STL_LIBDIR)

all: $(EXE2) $(EXE1)

$(EXE1): $(CCOBJS1)
	$(CXX) -v -static $(CXX_LDFLAGS) -o $@ $(CCOBJS1) $(LIBM) $(CXXLIBS)

$(EXE2): $(CCOBJS2)
	$(CXX) -v -static $(CXX_LDFLAGS) -o $@ $(CCOBJS2) $(LIBM) $(CXXLIBS)

$(CCOBJS1): $(CCSRC1)
	$(CXX) -v -static -c $(CXXFLAGS) -o $@ $(CCSRC1)

$(CCOBJS2): $(CCSRC2)
	$(CXX) -v -static -c $(CXXFLAGS) -o $@ $(CCSRC2)

romfs:
	$(ROMFSINST) /bin/$(EXE1)
	$(ROMFSINST) /bin/$(EXE2)

clean:
	rm -f *.o $(EXE1) $(EXE2) *.gdb


