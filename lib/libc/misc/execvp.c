
#include <unistd.h>

extern char ** environ;

int execvp(const char *file, char *const argv[])
{
	return execvep(file, argv, environ);
}
