
char **environ;

int
__uClibc_main(argc, argv, envp)
	int argc;
	char *argv[];
	char *envp[];
{
	environ = envp;
	exit(main(argc, argv, envp));
}

