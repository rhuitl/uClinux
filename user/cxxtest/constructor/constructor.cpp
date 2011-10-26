/*COPYRIGHT*/

#include <stdio.h>
#include <iostream>

using namespace std;

class foobarClass {
    public: 
        foobarClass() { value = 666; }
        ~foobarClass() {}
        int getValue() { return(value); }            
    private:
        int value;
};

foobarClass nonstaticGlobalFoobar;
foobarClass staticGlobalFoobar;

int
main(int argc, char *argv[]) {
    /* Test the constructors.
     */
    foobarClass nonstaticFoobar;
    static foobarClass staticFoobar;

    printf("Static Global Class Value = %d\n", staticGlobalFoobar.getValue());
    printf("Nonstatic Global Class Value = %d\n", nonstaticGlobalFoobar.getValue());
    printf("Static Class Value = %d\n", staticFoobar.getValue());
    printf("Nonstatic Class Value = %d\n", nonstaticFoobar.getValue());

    /* Test streams.
     */
    int foo = 1;
    cerr << "foobar" << endl;

    return 0;
}

