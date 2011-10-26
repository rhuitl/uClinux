#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdm++>


int main (int argc, char *argv[])
{
	printf("testing\n");
	MATT::out << "Hello, world\n";
	if (argc > 1) {
		for (;;)
			sleep(0);
	}
	exit(0);
}
