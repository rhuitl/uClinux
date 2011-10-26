/* #include <stdlib.h> */
#include <unistd.h>

int N;
char *p;

int main (int argc, char *argv[])
{
    if (argc != 2) {
        printf ("usage: consume <N> where N = the number of K bytes to consume\n");
        exit (1);
    }


    N = atoi (argv[1]);
    if (N == 0) {
        printf ("error: unable to parse \"%s\" as an integer\n", argv[1]);
        exit (1);
    }

    p = (char *)malloc (1024 * N);

    while (1) sleep (1);

    exit (0);
}
