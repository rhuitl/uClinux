
#include <unistd.h>
#include <stdarg.h>

extern char ** environ;

int execl(const char *path, const char *arg, ...)
{
	char *shortargv[16];
	char **argv;
	const char * c;
	int i;
	va_list args;
	
	i = 1;
	
	va_start(args, arg);

	do {
	  c = va_arg (args, const char *);
	  i++;
	} while (c);
	
	va_end(args);
	
	if (i <= 16)
		argv = shortargv;
	else {
		argv = (char**)malloc(sizeof(char*) * i);
	}

	argv[0] = (char *)arg;
	i = 1;
	
	va_start(args, arg);

	do {
	  argv[i] = va_arg (args, char *);
	} while (argv[i++]);
	
	va_end(args);
	
	i = execve(path, argv, environ);
	
	if (argv != shortargv)
		free(argv);
	
	return i;
}
