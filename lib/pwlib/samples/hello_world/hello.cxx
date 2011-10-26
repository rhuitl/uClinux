//
// hello.cxx
//
// Equivalence Pty. Ltd.
//

#include <ptlib.h>

class Hello : public PProcess
{
  PCLASSINFO(Hello, PProcess)
  public:
    void Main();
};

PCREATE_PROCESS(Hello)

void Hello::Main()
{
  cout << "Hello world!\n";
}

// End of hello.cxx
