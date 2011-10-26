EXE=cxx_shared
SRC=main.cxx
OBJ=$(SRC:.cxx=.o)
CXXFLAGS += -I ../lib

$(EXE): $(OBJ)
	$(CXX) $(CXX_LDFLAGS) -o $(EXE) $(OBJ) -L../lib -lstdm++ $(CXXLIBS)

$(OBJ):$(SRC)
	$(CXX) -c $(CXXFLAGS) -o $(OBJ) $(SRC)

clean:
	-rm -f *.o $(EXE)
