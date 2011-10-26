#include <unistd.h>

//#include <stdio.h>

using namespace std;

#define ENTERING "Entering the exception program\n"
#define EXCEPTION "Exception thrown\n"
#define HANDLING "Handling Exception\n"
#define HANDLED "Exception handled\n"
#define UNHANDLED "Exception not handled\n"

class MyException
{
   public:
      MyException() {}
      MyException(const MyException& copy) { write(STDERR_FILENO, EXCEPTION, sizeof (EXCEPTION) - 1);
}
};

void test(void)
{
   throw MyException();
}

int main()
{
	write(STDERR_FILENO, ENTERING, sizeof(ENTERING) - 1); 

   try
   {
      test();
//      fprintf(stderr, "Test succeeded\n");
	write(STDERR_FILENO, HANDLED, sizeof(HANDLED) - 1);
   }
   catch (MyException mx)
   {
 //     fprintf(stderr, "Caught MyException exception: \n");
	write(STDERR_FILENO, HANDLING, sizeof(HANDLING) - 1);
   }
   catch (...)
   {
	write(STDERR_FILENO, UNHANDLED, sizeof(UNHANDLED) -1 );
//         fprintf(stderr, "Unhandled exception\n");
//      cout << "Unhandled exception." << endl;
   }

   return 0;
}

