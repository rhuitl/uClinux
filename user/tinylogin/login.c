/* vi: set sw=4 ts=4: */
#include "tinylogin.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#include <utmp.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>


// login defines
#define LOGIN_PROMPT "\n%s login: "


/* From env.c */
extern char **newenvp;
extern size_t newenvc;


/* Stuff global to this file */
struct utmp utent;
struct passwd pwent;

static int su_mode = 0;

static void check_nologin();

#if defined TLG_FEATURE_SECURETTY
static int check_tty(const char *tty);
#else
/* #define check_tty(foo) 0 */
#define check_tty(foo) 1
#endif

static int is_my_tty();
static void login_prompt();
static void motd();
static int pw_auth();
static int set_uid_gid();

static void alarm_handler()
{
	error_msg("\nLogin timed out after %d seconds.\n", TIMEOUT);
	exit(EXIT_SUCCESS);
}




extern int login_main(int argc, char **argv)
{
	char name[32];
	char tty[BUFSIZ];
	char full_tty[200];
	char fromhost[512];
	char *host = "";
	char *cp = NULL;
	char *tmp;
	int amroot;
	int flag;
	int fflg = 0, hflg = 0, pflg = 0;
	int failed;
	int count=0;
	struct passwd *pwd;
	time_t start, now;

#ifdef TLG_FEATURE_SHADOWPASSWDS
	struct spwd *spwd = NULL;
#endif							/* TLG_FEATURE_SHADOWPASSWDS */
	char **envp = environ;

	initenv();
	name[0] = '\0';
	amroot = (getuid() == 0);
	signal(SIGALRM, alarm_handler);
	while ((flag = getopt(argc, argv, "f:h:d:p")) != EOF) {
		switch (flag) {
		case 'p':
			pflg++;
			break;
		case 'f':
			/*
			 * username must be a seperate token
			 * (-f root, *NOT* -froot). --marekm
			 */
			if (optarg != argv[optind - 1]) {
				usage(login_usage);
			}
			if (!amroot) {		/* Auth bypass only if real UID is zero */
				error_msg_and_die("login: -f permission denied\n");
			}
			fflg++;
			STRFCPY(name, optarg);
			break;
		case 'h':
			hflg++;
			host = optarg;
			break;
		default:
			usage(login_usage);
		}
	}
	if (!isatty(0) || !isatty(1) || !isatty(2)) {
		exit(EXIT_FAILURE);		/* Must be a terminal */
	}

	/* XXX su_mode */
	if (!su_mode) {
		checkutmp(!amroot);
	}

	tmp = ttyname(0);
	if (tmp == NULL)
		STRFCPY(tty, "UNKNOWN");
	else {
		if (!strncmp(tmp, "/dev/", 5)) {
			STRFCPY(tty, tmp + 5);
		} else
			STRFCPY(tty, "UNKNOWN");
	}
	if (amroot) {
		bzero(utent.ut_host, sizeof utent.ut_host);
	}
	if (hflg) {
		strncpy(utent.ut_host, host, sizeof(utent.ut_host));
		cp = host;
	}
	openlog("login", LOG_PID | LOG_CONS | LOG_NOWAIT, LOG_AUTH);
	if (pflg) {
		while (*envp) {
			addenv(*envp++, NULL);
		}
	}
	if (!pflg && (tmp = getenv("TERM"))) {
		addenv("TERM", tmp);
	}
	if (optind < argc) {
		STRFCPY(name, argv[optind]);
		optind++;
	}
	if (optind < argc) {		// Set command line variables
		set_env(argc - optind, &argv[optind]);
	}
	if (cp != NULL) {
		snprintf(fromhost, sizeof(fromhost), " on `%.100s' from `%.200s'",
				 tty, cp);
	} else {
		snprintf(fromhost, sizeof(fromhost), " on `%.100s'", tty);
	}
	if (TIMEOUT > 0) {
		alarm(TIMEOUT);
	}
	environ = newenvp;

	while (count<3) {
		failed = 0;
		if (!name[0]) {
			login_prompt(LOGIN_PROMPT, name, sizeof name);
		}
		if (!(pwd = tlg_getpwnam(name))) {
			pwent.pw_name = name;
			pwent.pw_passwd = "!";
			pwent.pw_shell = "/bin/sh";
			fflg = 0;
			failed = 1;
		} else {
			pwent = *pwd;
		}
#ifdef TLG_FEATURE_SHADOWPASSWDS
		spwd = NULL;
		if (pwd && ((strcmp(pwd->pw_passwd, "x") == 0)
					|| (strcmp(pwd->pw_passwd, "*") == 0))) {
			spwd = getspnam(name);
			if (spwd) {
				pwent.pw_passwd = spwd->sp_pwdp;
			} else {
				error_msg_and_die("no shadow password for `%s'%s\n", name,
								  fromhost);
			}
		}
#endif							/* TLG_FEATURE_SHADOWPASSWDS */
		if (pwent.pw_passwd[0] == '!' || pwent.pw_passwd[0] == '*') {
			failed = 1;
		}
		if (fflg) {
			fflg--;
			goto auth_ok;
		}

		/* If already root and su'ing don't ask for a password */
		if (amroot && su_mode)
			goto auth_ok;

		/* Don't check /etc/securetty if su'ing. */
		if (!su_mode && (pwent.pw_uid == 0) && (!check_tty(tty))) {
			failed = 1;
		}
		if (pwent.pw_passwd[0] == '\0') {
			goto auth_ok;
		}
		if (pw_auth(pwent.pw_passwd, name) == 0) {
			goto auth_ok;
		}
		syslog(LOG_WARNING, "invalid password for `%s'%s\n",
			   pwd ? name : "UNKNOWN", fromhost);
		failed = 1;
	  auth_ok:
		if (!failed) {
			break;
		}
		if (pwent.pw_passwd[0] == '\0') {
			pw_auth("!", name);
		}
		bzero(name, sizeof name);
		time(&start);
		now = start;
		while (difftime(now, start) < FAIL_DELAY) {
			sleep(FAIL_DELAY);
			time(&now);
		}

		/* XXX su_mode */
		if (su_mode) {
			error_msg_and_die("su: incorrect password\n");
		} else {
			puts("Login incorrect");
		}
		count++;
	}
	if (count>=3)
		exit (EXIT_FAILURE);
	(void) alarm(0);
	check_nologin();
	if (getenv("IFS")) {
		addenv("IFS= \t\n", NULL);
	}
	setutmp(name, tty);
	if (*tty != '/') {
		snprintf(full_tty, sizeof full_tty, "/dev/%s", tty);
	} else {
		strncpy(full_tty, tty, sizeof full_tty);
	}
	if (!is_my_tty(full_tty)) {
		syslog(LOG_ERR, "unable to determine TTY name, got %s\n",
			   full_tty);
	}
	/* Try these, but don't complain if they fail 
	 * (for example when the root fs is read only) */
	chown(full_tty, pwent.pw_uid, pwent.pw_gid);
	chmod(full_tty, 0600);

	if (set_uid_gid() != 0) {
		exit(EXIT_FAILURE);
	}
	setup_env(&pwent);
	motd();
	signal(SIGINT, SIG_DFL);	/* default interrupt signal */
	signal(SIGQUIT, SIG_DFL);	/* default quit signal */
	signal(SIGTERM, SIG_DFL);	/* default terminate signal */
	signal(SIGALRM, SIG_DFL);	/* default alarm signal */
	signal(SIGHUP, SIG_DFL);	/* added this.  --marekm */
	tlg_endpwent();					/* stop access to password file */
	tlg_endgrent();					/* stop access to group file */
#ifdef TLG_FEATURE_SHADOWPASSWDS
	endspent();					/* stop access to shadow passwd file */
//  endsgent();                    /* stop access to shadow group file */
#endif							/* TLG_FEATURE_SHADOWPASSWDS */
	if (pwent.pw_uid == 0) {
		syslog(LOG_INFO, "root login %s\n", fromhost);
	}
	closelog();
	shell(pwent.pw_shell, (char *) 0);	/* exec the shell finally. */
	 /*NOTREACHED*/ return (0);
}





static void check_nologin()
{
	if (access(NOLOGIN_FILE, F_OK) == 0) {
		FILE *nlfp;
		int c;

		if ((nlfp = fopen(NOLOGIN_FILE, "r"))) {
			while ((c = getc(nlfp)) != EOF) {
				if (c == '\n')
					putchar('\r');
				putchar(c);
			}
			fflush(stdout);
			fclose(nlfp);
		} else {
			printf("\r\nSystem closed for routine maintenance.\r\n");
		}
		if (pwent.pw_uid != 0) {
			closelog();
			exit(EXIT_SUCCESS);
		}
		printf("\r\n[Disconnect bypassed -- root login allowed.]\r\n");
	}
}

#ifdef TLG_FEATURE_SECURETTY
static int check_tty(const char *tty)
{
	FILE *fp;
	int i;
	char buf[BUFSIZ];

	if ((fp = fopen("/etc/securetty", "r")) == NULL) {
		syslog(LOG_WARNING, "cannot open securetty file.\n");
		/* return 0; */
		return 1;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		for (i = strlen(buf) - 1; i >= 0; --i) {
			if (!isspace(buf[i])) {
				break;
			}
		}
		buf[++i] = '\0';
		if (buf[0] == '\0' || buf[0] == '#') {
			continue;
		}
		if (strcmp(buf, tty) == 0) {
			fclose(fp);
			/* return 0; */
			return 1;
		}
	}
	fclose(fp);
	/* return 1; */
	return 0;
}
#endif							/* TLG_FEATURE_SECURETTY */

/* returns 1 if true */
static int is_my_tty(const char *tty)
{
	struct stat by_name, by_fd;

	if (stat(tty, &by_name) || fstat(0, &by_fd)) {
		return 0;
	}
	if (by_name.st_rdev != by_fd.st_rdev) {
		return 0;
	} else {
		return 1;
	}
}

static void login_prompt(const char *prompt, char *name, int namesize)
{
	char buf[1024];
	char *cp;
	int i;
	void (*sigquit) ();

	sigquit = signal(SIGQUIT, _exit);
	if (prompt) {
		gethostname(buf, sizeof buf);
		printf(prompt, buf);
		fflush(stdout);
	}
	bzero(buf, sizeof buf);
	if (fgets(buf, sizeof buf, stdin) != buf) {
		exit(EXIT_FAILURE);
	}
	cp = strchr(buf, '\n');
	if (!cp) {
		exit(EXIT_FAILURE);
	}
	*cp = '\0';

	for (cp = buf; *cp == ' ' || *cp == '\t'; cp++);
	for (i = 0; i < namesize - 1 && isgraph(*cp); name[i++] = *cp++);
	while (isgraph(*cp)) {
		cp++;
	}
	if (*cp) {
		cp++;
	}
	name[i] = '\0';
	signal(SIGQUIT, sigquit);
}

static void motd()
{
	FILE *fp;
	register int c;

	if ((fp = fopen("/etc/motd", "r")) != NULL) {
		while ((c = getc(fp)) != EOF) {
			putchar(c);
		}
		fflush(stdout);
		fclose(fp);
	}
}

static int pw_auth(const char *cipher, const char *user)
{
	char *clear = NULL;
	int retval;

	if (cipher == (char *) 0 || *cipher == '\0') {
		return 0;
	}
	clear = getpass("Password: ");
	if (!clear) {
		static char c[1];

		c[0] = '\0';
		clear = c;
	}
	retval = strcmp(pw_encrypt(clear, cipher), cipher);
	bzero(clear, strlen(clear));
	return retval;
}

static int set_uid_gid()
{
	if (tlg_initgroups(pwent.pw_name, pwent.pw_gid) == -1) {
		perror("initgroups");
		syslog(LOG_ERR, "initgroups failed for user `%s': %m\n",
			   pwent.pw_name);
		closelog();
		/* return -1; */
		return 1;
	}
	if (setgid(pwent.pw_gid) == -1) {
		perror("setgid");
		syslog(LOG_ERR, "bad group ID `%d' for user `%s': %m\n",
			   pwent.pw_gid, pwent.pw_name);
		closelog();
		/* return -1; */
		return 1;
	}
	if (setuid(pwent.pw_uid)) {
		perror("setuid");
		syslog(LOG_ERR, "bad user ID `%d' for user `%s': %m\n",
			   pwent.pw_uid, pwent.pw_name);
		closelog();
		/* return -1; */
		return 1;
	}
	return 0;
}

#ifdef TLG_SU
/* + Construct an argv that login_main() can parse.
 * + For options that can't be specified on argv,
 *   modify global variables.  (ewwww)
 * + return argc
 */
static int
construct_argv(
			   char **argv,
			   char *username, int preserve, char *shell, char *command)
{
	int argc = 0;

	argv[argc++] = "su";
	if (preserve) {
		argv[argc++] = "-p";
	}
	argv[argc++] = username;

	argv[argc] = NULL;
	return argc;
}


/* 
 * TODO : I need to see if I can support the lone dash option.
 *      : I need to try to support the other options
 *      : -* poor schizophrenic login_main() *-
 `.________________________________________________________________________ */
int su_main(int argc, char **argv)
{
	int flag;
	int opt_preserve = 0;
	int opt_loginshell = 0;
	char *opt_shell = NULL;
	char *opt_command = NULL;
	char *username = "root";

	char *custom_argv[16];
	int custom_argc;

	su_mode = 1;

	/* su called w/ no args */
	if (argc == 1) {
		custom_argc = construct_argv(custom_argv,
									 username,
									 opt_preserve, opt_shell, opt_command);
		return login_main(custom_argc, custom_argv);
	}

	/* getopt */
	while ((flag = getopt(argc, argv, "c:hmps:")) != EOF) {
		switch (flag) {

		case 'c':
			opt_command = optarg;
			break;

		case 'h':
			usage(su_usage);
			break;

		case 'm':
		case 'p':
			opt_preserve = 1;
			break;

		case 's':
			opt_shell = optarg;
			break;

		default:
			usage(su_usage);
			break;
		}
	}

	/* get user if specified */
	if (optind < argc) {
		if (strcmp(argv[optind], "-") == 0) {
			opt_loginshell = 1;
			if ((optind + 1) < argc) {
				username = argv[++optind];
			}
		} else {
			username = argv[optind];
		}
		optind++;
	}

	/* construct custom_argv */
	custom_argc = construct_argv(custom_argv,
								 username,
								 opt_preserve, opt_shell, opt_command);

	/* reset getopt | how close to kosher is this? | damn globals */
	optind = 0;

	return login_main(custom_argc, custom_argv);
}
#endif							/* TLG_SU */
