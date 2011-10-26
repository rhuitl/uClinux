/*
 * Copyright (c) 1993 by David I. Bell
 * Permission is granted to use, distribute, or modify this source,
 * provided that this copyright notice remains intact.
 *
 * Stand-alone shell for system maintainance for Linux.
 * This program should NOT be built using shared libraries.
 *
 * 1.1.1, 	hacked to re-allow cmd line invocation of script file
 *		Pat Adamo, padamo@unix.asb.com
 */

#include "sash.h"

#ifndef CMD_HELP
#define	CMD_HELP
#endif
#undef INTERNAL_PATH_EXPANSION
#define FAVOUR_EXTERNAL_COMMANDS

#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

static char version[] = "1.1.1";

extern int intflag;

extern void do_test();

typedef struct {
	char	name[10];
	char	usage[30];
	void	(*func)();
	int	minargs;
	int	maxargs;
} CMDTAB;


CMDTAB	cmdtab[] = {
/*
	"alias",	"[name [command]]", 	do_alias,
	1,		MAXARGS,
*/
	"cd",		"[dirname]",		do_cd,
	1,		2,
			
	"sleep",		"seconds",		do_sleep,
	1,		2,

	"chgrp",	"gid filename ...",	do_chgrp,
	3,		MAXARGS,

	"chmod",	"mode filename ...",	do_chmod,
	3,		MAXARGS,

	"chown",	"uid filename ...",	do_chown,
	3,		MAXARGS,

	"cmp",		"filename1 filename2",	do_cmp,
	3,		3,

	"cp",		"srcname ... destname",	do_cp,
	3,		MAXARGS,

/*
	"dd",		"if=name of=name [bs=n] [count=n] [skip=n] [seek=n]", do_dd,
	3,		MAXARGS,
*/
	"df",		"[file-system]",	do_df,
	1,		2,

	"echo",	"[args] ...",			do_echo,
	1,		MAXARGS,

/*
	"ed",		"[filename]",		do_ed,
	1,		2,
*/

	"exec",		"filename [args]",	do_exec,
	2,		MAXARGS,

	"exit",		"",			do_exit,
	1,		1,

	"free",		"",			do_free,
	1,		1,

/*
	"-grep",	"[-in] word filename ...",	do_grep,
	3,		MAXARGS,
*/

#ifdef CMD_HELP
	"help",		"",			do_help,
	1,		MAXARGS,
#endif

	"hexdump",	"[-s pos] filename",	do_hexdump,
	1,		4,

	"hostname",	"[hostname]",		do_hostname,
	1,		2,

	"kill",		"[-sig] pid ...",	do_kill,
	2,		MAXARGS,

	"ln",		"[-s] srcname ... destname",	do_ln,
	3,		MAXARGS,

	"ls",		"[-lidC] filename ...",	do_ls,
	1,		MAXARGS,

	"mkdir",	"dirname ...",		do_mkdir,
	2,		MAXARGS,

	"mknod",	"filename type major minor",	do_mknod,
	5,		5,

	"more",	"filename ...",		do_more,
	2,		MAXARGS,

	"mount",	"[-t type] devname dirname",	do_mount,
	3,		MAXARGS,

	"mv",		"srcname ... destname",	do_mv,
	3,		MAXARGS,

	"printenv",	"[name]",		do_printenv,
	1,		2,

	"pwd",		"",			do_pwd,
	1,		1,

	"pid",		"",			do_pid,
	1,		1,

	"quit",		"",			do_exit,
	1,		1,

	"rm",		"filename ...",		do_rm,
	2,		MAXARGS,

	"rmdir",	"dirname ...",		do_rmdir,
	2,		MAXARGS,

	"setenv",	"name value",		do_setenv,
	3,		3,

	"source",	"filename",		do_source,
	2,		2,

	"sync",	"",			do_sync,
	1,		1,

/*	"time",	"",			do_time,
	1,		1,
*/
/*
	"tar",		"[xtv]f devname filename ...",	do_tar,
	2,		MAXARGS,
*/
	"touch",	"filename ...",		do_touch,
	2,		MAXARGS,

	"umask",	"[mask]",		do_umask,
	1,		2,

	"umount",	"filename",		do_umount,
	2,		2,

/*
	"unalias",	"name",			do_unalias,
	2,		2,
*/
#ifdef CONFIG_USER_SASH_PS
	"ps",		"",			do_ps,
	1,		MAXARGS,
#endif

/*	"reboot",	"",			do_reboot,
	1,		MAXARGS,
*/
	"cat",		"filename ...",		do_cat,
	2,		MAXARGS,

	"date",		"date [MMDDhhmm[YYYY]]",	do_date,
	1,		2,

	0,		0,			0,
	0,		0
};


typedef struct {
	char	*name;
	char	*value;
} ALIAS;


static	ALIAS	*aliastable;
static	int	aliascount;

static	FILE	*sourcefiles[MAXSOURCE];
static	int	sourcecount;

volatile static	BOOL	intcrlf = TRUE;


static	void	catchint();
static	void	catchquit();
static	void	catchchild();
static	void	readfile();
static	void	command();
#ifdef COMMAND_HISTORY
#define do_command(c,h)	command(c,h)
#else
#define do_command(c,h)	command(c)
#endif
static	void	runcmd();
static	void	showprompt();
static	BOOL	trybuiltin();
static	BOOL	command_in_path();
static	ALIAS	*findalias();

extern char ** environ;

/* 
char text1[] = "Text";
char * text2 = text1;
char ** text3 = &text2;
*/

char	buf[CMDLEN];
int exit_code = 0;

main(argc, argv, env)
	char	**argv;
	char	*env[];
{
	struct sigaction act;
	char	*cp;
/*	char	buf[PATHLEN];*/
	int dofile = 0;
	
	if ((argc > 1) && !strcmp(argv[1], "-c")) {
		/* We are that fancy a shell */
		buf[0] = '\0';
		for (dofile = 2; dofile < argc; dofile++) {
			strncat(buf, argv[dofile], sizeof(buf));
			if (dofile + 1 < argc)
				strncat(buf, " ", sizeof(buf));
		}
		do_command(buf, FALSE);
		exit(exit_code);
	}

	//;'pa990523 +
	if ((argc > 1) && strcmp(argv[1], "-t"))
		{
		dofile++;
		printf("Shell invoked to run file: %s\n",argv[1]);
		}
	else
		printf("\nSash command shell (version %s)\n", version);
	fflush(stdout);

	signal(SIGINT, catchint);
	signal(SIGQUIT, catchquit);

	memset(&act, 0, sizeof(act));
	act.sa_handler = catchchild;
	act.sa_flags = SA_RESTART;
	sigaction(SIGCHLD, &act, NULL);

	if (getenv("PATH") == NULL)
		putenv("PATH=/bin:/usr/bin:/etc:/sbin:/usr/sbin");

/*	cp = getenv("HOME");
	if (cp) {
		strcpy(buf, cp);
		strcat(buf, "/");
		strcat(buf, ".aliasrc");

		if ((access(buf, 0) == 0) || (errno != ENOENT))
			readfile(buf);
	}
*/	
	//;'pa990523 -1/+
	//readfile(NULL);
	if (dofile)
		{
		//open the file for reading!
		readfile(argv[1]);
		}
	   else
		{
		readfile(NULL); //no arguments!
		} //end if arguments supplied
	exit(exit_code);
}


/*
 * Read commands from the specified file.
 * A null name pointer indicates to read from stdin.
 */
static void
readfile(name)
	char	*name;
{
	FILE	*fp;
	int	cc;
	BOOL	ttyflag;
	char	*ptr;

	if (sourcecount >= MAXSOURCE) {
		fprintf(stderr, "Too many source files\n");
		return;
	}

	fp = stdin;
	if (name) {
		fp = fopen(name, "r");
		if (fp == NULL) {
			perror(name);
			return;
		}
	}
	sourcefiles[sourcecount++] = fp;

	ttyflag = isatty(fileno(fp));

	while (TRUE) {
		fflush(stdout);
		//;'pa990523 -1/+1
		//if (1)
		if (fp == stdin) //using terminal, so show prompt
			showprompt();

		if (intflag && !ttyflag && (fp != stdin)) {
			fclose(fp);
			sourcecount--;
			return;
		}

		if (fgets(buf, CMDLEN - 1, fp) == NULL) {
			if (ferror(fp) && (errno == EINTR)) {
				clearerr(fp);
				continue;
			}
			break;
		}

		cc = strlen(buf);

		while ((cc > 0) && isspace(buf[cc - 1]))
			cc--;
		buf[cc] = '\0';
		/* remove leading spaces and look for a '#' */
		ptr = &buf[0];
		while (*ptr == ' ') {
			ptr++;
		}
		if (*ptr != '#') {
			//;'pa990523 +
			if (fp != stdin) {
				//taking commands from file - echo
				printf("Command: %s\n",buf);
			} //end if (fp != stdin)

			do_command(buf, fp == stdin);
		}
	}



	if (ferror(fp)) {
		perror("Reading command line");
		if (fp == stdin)
			exit(1);
	}

	clearerr(fp);
	if (fp != stdin)
		{//;'pa990523 added braces and printf
		fclose(fp);
		printf("Execution Finished, Exiting\n");
		} //end if (fp != stdin)

	sourcecount--;
}


/*
 * Parse and execute one null-terminated command line string.
 * This breaks the command line up into words, checks to see if the
 * command is an alias, and expands wildcards.
 */
static void
#ifdef COMMAND_HISTORY
command(cmd, do_history)
	int do_history;
#else
command(cmd)
#endif
	char	*cmd;
{
	ALIAS	*alias;
	char	**argv;
	int	argc;
	int 	bg;
	char   *c;

	char last_exit_code[10];

	sprintf(last_exit_code, "%d", exit_code);

	intflag = FALSE;
	exit_code = 0;

	freechunks();

	while (isblank(*cmd))
		cmd++;

#ifdef COMMAND_HISTORY
	if (do_history) {
		int i;
		static char *history[HISTORY_SIZE];

		if (*cmd == '!') {
			if (cmd[1] == '!')
				i = 0;
			else {
				i = atoi(cmd+1) - 1;
				if (i < 0 || i >= HISTORY_SIZE) {
					printf("%s: Out of range\n", cmd);
					return;
				}
			}
			if (history[i] == NULL) {
				printf("%s: Null entry\n", cmd);
				return;
			}
			strcpy(cmd, history[i]);
		} else if (*cmd == 'h' && cmd[1] == '\0') {
			for (i=0; i<HISTORY_SIZE; i++) {
				if (history[i] != NULL)
					printf("%2d: %s\n", i+1, history[i]);
			}
			return;
		} else if (*cmd != '\0') {
			if (history[HISTORY_SIZE-1] != NULL)
				free(history[HISTORY_SIZE-1]);
			for (i=HISTORY_SIZE-1; i>0; i--)
				history[i] = history[i-1];
			history[0] = strdup(cmd);
		}
	}
#endif
	if (c = strchr(cmd, '&')) {
		*c = '\0';
		bg = 1;
	} else
		bg = 0;

	/* Set the last exit code */
	setenv("?", last_exit_code, 1);
	
	if ((cmd = expandenvvar(cmd)) == NULL)
		return;

	if ((*cmd == '\0') || !makeargs(cmd, &argc, &argv))
		return;

	/*
	 * Search for the command in the alias table.
	 * If it is found, then replace the command name with
	 * the alias, and append any other arguments to it.
	 */
	alias = findalias(argv[0]);
	if (alias) {
		cmd = buf;
		strcpy(cmd, alias->value);

		while (--argc > 0) {
			strcat(cmd, " ");
			strcat(cmd, *++argv);
		}

		if (!makeargs(cmd, &argc, &argv))
			return;
	}

	/*
	 * BASH-style variable setting
	 */
	if (argc == 1) {
		c = index(argv[0], '=');
		if (c > argv[0]) {
			*c++ = '\0';
			setenv(argv[0], c, 1);
			return;
		}
	}
		
	/*
	 * Now look for the command in the builtin table, and execute
	 * the command if found.
	 */
#ifdef FAVOUR_EXTERNAL_COMMANDS
	if (!command_in_path(argv[0]))
#endif
	if (trybuiltin(argc, argv))
		return;

	/*
	 * Not found, run the program along the PATH list.
	 */
	runcmd(cmd, bg, argc, argv);
}


#ifdef FAVOUR_EXTERNAL_COMMANDS
/*
 * return true if we find this command in our
 * path.
 */
static BOOL
command_in_path(char *cmd)
{
	struct stat	stat_buf;

	if (strchr(cmd, '/') == 0) {
		char	* path;
		static char	path_copy[PATHLEN];
		
		/* Search path for binary */
		for (path = getenv("PATH"); path && *path; ) {
			char * p2;

			strcpy(path_copy, path);
			if (p2 = strchr(path_copy, ':')) {
				*p2 = '\0';
			}
		
			if (strlen(path_copy))
				strcat(path_copy, "/");
			strcat(path_copy, cmd);
			
			if (!stat(path_copy, &stat_buf) && (stat_buf.st_mode & 0111))
				return(TRUE);
			
			p2 = strchr(path, ':');
			if (p2)
				path = p2 + 1;
			else
				path = 0;
		}
	} else if (!stat(cmd, &stat_buf) && (stat_buf.st_mode & 0111))
		return(TRUE);
	return(FALSE);
}
#endif /* FAVOUR_EXTERNAL_COMMANDS */


/*
 * Try to execute a built-in command.
 * Returns TRUE if the command is a built in, whether or not the
 * command succeeds.  Returns FALSE if this is not a built-in command.
 */
static BOOL
trybuiltin(argc, argv)
	char	**argv;
{
	CMDTAB	*cmdptr;
	int	oac;
	int	newargc;
	int	matches;
	int	i;
	char	*newargv[MAXARGS];
	char	*nametable[MAXARGS];

	cmdptr = cmdtab - 1;
	do {
		cmdptr++;
		if (cmdptr->name[0] == 0)
			return FALSE;

	} while (strcmp(argv[0], cmdptr->name));
	
	/*
	 * Give a usage string if the number of arguments is too large
	 * or too small.
	 */
	if ((argc < cmdptr->minargs) || (argc > cmdptr->maxargs)) {
		fprintf(stderr, "usage: %s %s\n",
			cmdptr->name, cmdptr->usage);
		fflush(stderr);

		return TRUE;
	}

	/*
	 * Check here for several special commands which do not
	 * have wildcarding done for them.
	 */

/*        if (cmdptr->func == do_prompt) {
		(*cmdptr->func)(argc, argv);
		return TRUE;
	}
*/

	/*
	 * Now for each command argument, see if it is a wildcard, and if
	 * so, replace the argument with the list of matching filenames.
	 */
	newargv[0] = argv[0];
	newargc = 1;
	oac = 0;

	while (++oac < argc) {
		if (argv[oac][0] == '"' || argv[oac][0] == '\'') {
			argv[oac]++;
			matches = 0;
		}
		else {
			matches = expandwildcards(argv[oac], MAXARGS, nametable);
			if (matches < 0)
				return TRUE;
		}

		if ((newargc + matches) >= MAXARGS) {
			fprintf(stderr, "Too many arguments\n");
			return TRUE;
		}

		if (matches == 0)
			newargv[newargc++] = argv[oac];

		for (i = 0; i < matches; i++)
			newargv[newargc++] = nametable[i];
	}

	(*cmdptr->func)(newargc, newargv);

	return TRUE;
}


/*
 * Execute the specified command.
 */
static void
runcmd(cmd, bg, argc, argv)
	char	*cmd;
	int	bg;
	int	argc;
	char	**argv;
{
	register char *	cp;
	BOOL		magic;
	int		pid;
	int		status;
	int oac;
	int newargc;
	int matches;
	int i;
	char	*newargv[MAXARGS];
	char	*nametable[MAXARGS];
	struct sigaction act;
	
	newargv[0] = argv[0];
	
#ifdef INTERNAL_PATH_EXPANSION
	if (strchr(argv[0], '/') == 0) {
		char	* path;
		struct stat	stat_buf;
		static char	path_copy[PATHLEN];
		
		/* Search path for binary */
		for (path = getenv("PATH"); path && *path; ) {
			char * p2;
			strncpy(path_copy, path, sizeof(path_copy - 1));
			if (p2 = strchr(path_copy, ':')) {
				*p2 = '\0';
			}
		
			if (strlen(path_copy))
				strncat(path_copy, "/", sizeof(path_copy));
			strncat(path_copy, argv[0], sizeof(path_copy));
			
			if (!stat(path_copy, &stat_buf) && (stat_buf.st_mode & 0111)) {
				newargv[0] = path_copy;
				break;
			}
			
			p2 = strchr(path, ':');
			if (p2)
				path = p2 + 1;
			else
				path = 0;
		}
	}
#endif

	/*
	 * Now for each command argument, see if it is a wildcard, and if
	 * so, replace the argument with the list of matching filenames.
	 */
	newargc = 1;
	oac = 0;

	while (++oac < argc) {
		if (argv[oac][0] == '"' || argv[oac][0] == '\'') {
			argv[oac]++;
			matches = 0;
		}
		else {
			matches = expandwildcards(argv[oac], MAXARGS, nametable);
			if (matches < 0)
				return;
		}

		if ((newargc + matches) >= MAXARGS) {
			fprintf(stderr, "Too many arguments\n");
			return;
		}

		if (matches == 0)
			newargv[newargc++] = argv[oac];

		for (i = 0; i < matches; i++)
			newargv[newargc++] = nametable[i];
	}
	
	newargv[newargc] = 0;

	magic = FALSE;
	
	/*
	for (cp = cmd; *cp; cp++) {
		if ((*cp >= 'a') && (*cp <= 'z'))
			continue;
		if ((*cp >= 'A') && (*cp <= 'Z'))
			continue;	
		if (isdecimal(*cp))
			continue;
		if (isblank(*cp))
			continue;

		if ((*cp == '.') || (*cp == '/') || (*cp == '-') ||
			(*cp == '+') || (*cp == '=') || (*cp == '_') ||
			(*cp == ':') || (*cp == ','))
				continue;

		magic = TRUE;
	}
	*/

	if (magic) {
		printf("%s: no such file or directory\n", cmd);
		system(cmd);
		return;
	}
	
	if (!bg)
		signal(SIGCHLD, SIG_DFL);

	/*
	 * No magic characters in the expanded command, so do the fork and
	 * exec ourself.  If this fails with ENOEXEC, then run the
	 * shell anyway since it might be a shell script.
	 */
	if (!(pid = vfork())) {
		int	ci;

		/*
		 * We are the child, so run the program.
		 * First close any extra file descriptors we have opened.
		 * be sure not to modify any globals after the vfork !
		 */	
		
		for (ci = 0; ci < sourcecount; ci++)
			if (sourcefiles[ci] != stdin)
				close(fileno(sourcefiles[ci]));
		
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		
		execvp(newargv[0], newargv);

		printf("%s: %s\n", newargv[0], (errno == ENOENT) ? "Bad command or file name" : strerror(errno));
		
		_exit(0);
	}
	
	if (pid < 0) {
		memset(&act, 0, sizeof(act));
		act.sa_handler = catchchild;
		act.sa_flags = SA_RESTART;
		sigaction(SIGCHLD, &act, NULL);

		perror("vfork failed");
		return;
	}
	
	if (bg) {
		printf("[%d]\n", pid);
		return;
	}

	if (pid) {
		int cpid;
		status = 0;
		intcrlf = FALSE;

		for (;;) {
			cpid = wait4(pid, &status, 0, 0);
			if ((cpid < 0) && (errno == EINTR))
				continue;
			if (cpid < 0)
				break;
			if (cpid != pid) {
				fprintf(stderr, "sh %d: child %d died\n", getpid(), cpid);
				continue;
			}
		}

		act.sa_handler = catchchild;
		memset(&act.sa_mask, 0, sizeof(act.sa_mask));
		act.sa_flags = SA_RESTART;
		sigaction(SIGCHLD, &act, NULL);
		
		intcrlf = TRUE;

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0)
				return;
			exit_code = WEXITSTATUS(status);
		} else
			exit_code = 1;

		return;
	}
	
	perror(argv[0]);
	exit(1);
}

#ifdef CMD_HELP
void
do_help(argc, argv)
	char	**argv;
{
	CMDTAB	*cmdptr;

	for (cmdptr = cmdtab; cmdptr->name && cmdptr->name[0]; cmdptr++)
		printf("%-10s %s\n", cmdptr->name, cmdptr->usage);
}
#endif /* CMD_HELP */

#ifdef CMD_ALIAS
void
do_alias(argc, argv)
	char	**argv;
{
	char	*name;
	char	*value;
	ALIAS	*alias;
	int	count;
	char	buf[CMDLEN];

	if (argc < 2) {
		count = aliascount;
		for (alias = aliastable; count-- > 0; alias++)
			printf("%s\t%s\n", alias->name, alias->value);
		return;
	}

	name = argv[1];
	if (argc == 2) {
		alias = findalias(name);
		if (alias)
			printf("%s\n", alias->value);
		else
			fprintf(stderr, "Alias \"%s\" is not defined\n", name);
		return;	
	}

	if (strcmp(name, "alias") == 0) {
		fprintf(stderr, "Cannot alias \"alias\"\n");
		return;
	}

	if (!makestring(argc - 2, argv + 2, buf, CMDLEN))
		return;

	value = malloc(strlen(buf) + 1);

	if (value == NULL) {
		fprintf(stderr, "No memory for alias value\n");
		return;
	}

	strcpy(value, buf);

	alias = findalias(name);
	if (alias) {
		free(alias->value);
		alias->value = value;
		return;
	}

	if ((aliascount % ALIASALLOC) == 0) {
		count = aliascount + ALIASALLOC;

		if (aliastable)
			alias = (ALIAS *) realloc(aliastable,
				sizeof(ALIAS *) * count);
		else
			alias = (ALIAS *) malloc(sizeof(ALIAS *) * count);

		if (alias == NULL) {
			free(value);
			fprintf(stderr, "No memory for alias table\n");
			return;
		}

		aliastable = alias;
	}

	alias = &aliastable[aliascount];

	alias->name = malloc(strlen(name) + 1);

	if (alias->name == NULL) {
		free(value);
		fprintf(stderr, "No memory for alias name\n");
		return;
	}

	strcpy(alias->name, name);
	alias->value = value;
	aliascount++;
}
#endif /* CMD_ALIAS */

/*
 * Look up an alias name, and return a pointer to it.
 * Returns NULL if the name does not exist.
 */
static ALIAS *
findalias(name)
	char	*name;
{
	ALIAS	*alias;
	int	count;

	count = aliascount;
	for (alias = aliastable; count-- > 0; alias++) {
		if (strcmp(name, alias->name) == 0)
			return alias;
	}

	return NULL;
}


void
do_source(argc, argv)
	char	**argv;
{
	readfile(argv[1]);
}

/*void
do_cd(argc, argv)
	char	**argv;
{
	char	*name;

	name = argv[1];
	
	if (chdir(name))
		perror("Unable to chdir to %s");
	
}*/

void
do_pid(argc, argv)
{
	printf("%d\n", getpid());
}

void
do_exec(argc, argv)
	char	**argv;
{
	while (--sourcecount >= 0) {
		if (sourcefiles[sourcecount] != stdin)
			fclose(sourcefiles[sourcecount]);
	}

	argv[argc] = NULL;
	execvp(argv[1], &argv[1]);

	perror(argv[1]);
	exit(1);
}

/*void
do_exit(argc, argv)
	char	**argv;
{
	if (argc>1)
		exit(atoi(argv[1]));
	else
		exit(0);
}*/


#ifdef CMD_ALIAS
void
do_unalias(argc, argv)
	char	**argv;
{
	ALIAS	*alias;

	while (--argc > 0) {
		alias = findalias(*++argv);
		if (alias == NULL)
			continue;

		free(alias->name);
		free(alias->value);
		aliascount--;
		alias->name = aliastable[aliascount].name;
		alias->value = aliastable[aliascount].value;	
	}
}
#endif /* CMD_ALIAS */

/*
 * Display the prompt string.
 */
static void
showprompt()
{
	char	*cp;
	//;'pa990523 changed from 6...
	char buf[60];
	
	if ((cp = getenv("PS1")) != NULL) {
		printf("%s", cp);
	}
	else {
		*buf = '\0';
		getcwd(buf, sizeof(buf) - 1);
		printf("%s> ", buf);
	}
	fflush(stdout);
}	


static void
catchint()
{
	signal(SIGINT, catchint);

	intflag = TRUE;

	if (intcrlf)
		write(STDOUT, "\n", 1);
}


static void
catchquit()
{
	signal(SIGQUIT, catchquit);

	intflag = TRUE;

	if (intcrlf)
		write(STDOUT, "\n", 1);
}

static void
catchchild()
{
	char buf[40];
	pid_t pid;
	int status;
	
	/*signal(SIGCHLD, catchchild);*/ /* Unneeded */

	pid = wait4(-1, &status, WUNTRACED, 0);
	if (WIFSTOPPED(status))
		sprintf(buf, "sh %d: Child %d stopped\n", getpid(), pid);
	else
		sprintf(buf, "sh %d: Child %d died\n", getpid(), pid);
	
	if (intcrlf)
		write(STDOUT, "\n", 1);
	
	write(STDOUT, buf, strlen(buf));
}

/* END CODE */
