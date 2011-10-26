lib=stdm++

SRC=stdm++.cxx
OBJ=$(SRC:.cxx=.o)

all: $(OBJ)
	$(AR) r libstdm++.a $(OBJ)
	-rm -f libstdm++.so
	$(CXX) $(CXXFLAGS) $(CXX_LDFLAGS) -shared -o libstdm++.so -Wl,--whole-archive ../lib/libstdm++.a -Wl,--no-whole-archive $(CXXLIBS)

$(OBJ):$(SRC)
	$(CXX) -c $(CXXFLAGS) -o $(OBJ) $(SRC)

clean:
	-rm -f *.a *.o *.so
