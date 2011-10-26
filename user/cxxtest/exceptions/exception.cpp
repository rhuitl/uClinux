#include <iostream>

using namespace std;

class MyException
{
   public:
      MyException() {}
      MyException(const MyException& copy) { cout << "copy called" << endl;
}
};

void test(void)
{
   throw MyException();
}

int main()
{
   cout << "program starting" << endl;

   try
   {
      test();
      cout << "Test succeeded." << endl;
   }
   catch (MyException mx)
   {
      cout << "Caught MyException exception: " << endl;
   }
   catch (...)
   {
      cout << "Unhandled exception." << endl;
   }

   return 0;
}

