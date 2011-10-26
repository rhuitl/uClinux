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




// sulogin defines
#define SULOGIN_PROMPT "\nGive root password for system maintenance\n" \
	"(or type Control-D for normal startup):"


// From env.c
extern char **newenvp;


static void catchalarm()
{
	exit(EXIT_FAILURE);
}


extern int sulogin_main(int argc, char **argv)
{
	char *cp;
	char *device = (char *) 0;
	char **envp = environ;
	char *name = "root";
	int timeout = 0;
	static char pass[BUFSIZ];
	struct termios termio;
	struct passwd pwent;
	struct passwd *pwd;
	time_t start, now;

#ifdef TLG_FEATURE_SHADOWPASSWDS
	struct spwd *spwd = NULL;
#endif							/* TLG_FEATURE_SHADOWPASSWDS */
	tcgetattr(0, &termio);
	termio.c_iflag |= (ICRNL | IXON);
	termio.c_oflag |= (CREAD);
	termio.c_lflag |= (ECHO | ECHOE | ECHOK | ICANON | ISIG);
	tcsetattr(0, TCSANOW, &termio);
	openlog("sulogin", LOG_PID | LOG_CONS | LOG_NOWAIT, LOG_AUTH);
	initenv();
	if (argc > 1) {
		if (strncmp(argv[1], "-t", 2) == 0) {
			if (strcmp(argv[1], "-t") == 0) {
				if (argc > 2) {
					timeout = atoi(argv[2]);
					if (argc > 3) {
						device = argv[3];
					}
				}
			} else {
				if (argc > 2) {
					device = argv[2];
				}
			}
		} else {
			device = argv[1];
		}
		if (device) {
			close(0);
			close(1);
			close(2);
			if (open(device, O_RDWR) >= 0) {
				dup(0);
				dup(0);
			} else {
				syslog(LOG_WARNING, "cannot open %s\n", device);
				exit(EXIT_FAILURE);
			}
		}
	}
	if (access(PASSWD_FILE, 0) == -1) {
		syslog(LOG_WARNING, "No password file\n");
		error_msg_and_die("No password file\n");
	}
	if (!isatty(0) || !isatty(1) || !isatty(2)) {
		exit(EXIT_FAILURE);
	}
	while (*envp) {
		addenv(*envp++, NULL);
	}
	signal(SIGALRM, catchalarm);
	alarm(timeout);
	if (!(pwd = tlg_getpwnam(name))) {
		syslog(LOG_WARNING, "No password entry for `root'\n");
		error_msg_and_die("No password entry for `root'\n");
	}
	pwent = *pwd;
#ifdef TLG_FEATURE_SHADOWPASSWDS
	spwd = NULL;
	if (pwd && ((strcmp(pwd->pw_passwd, "x") == 0)
				|| (strcmp(pwd->pw_passwd, "*") == 0))) {
		endspent();
		spwd = getspnam(name);
		if (spwd) {
			pwent.pw_passwd = spwd->sp_pwdp;
		}
	}
#endif							/* TLG_FEATURE_SHADOWPASSWDS */
	while (1) {
		cp = getpass(SULOGIN_PROMPT);
		if (!cp || !*cp) {
			syslog(LOG_INFO, "Normal startup\n");
			puts("\n");
			exit(EXIT_SUCCESS);
		} else {
			STRFCPY(pass, (cp));
			bzero(cp, strlen(cp));
		}
		if (strcmp(pw_encrypt(pass, pwent.pw_passwd), pwent.pw_passwd) == 0) {
			break;
		}
		syslog(LOG_WARNING, "Incorrect root password\n");
		time(&start);
		now = start;
		while (difftime(now, start) < FAIL_DELAY) {
			sleep(FAIL_DELAY);
			time(&now);
		}
		puts("Login incorrect");
	}
	bzero(pass, strlen(pass));
	alarm(0);
	signal(SIGALRM, SIG_DFL);
	environ = newenvp;
	puts("Entering System Maintenance Mode\n");
	syslog(LOG_INFO, "System Maintenance Mode\n");
	shell(pwent.pw_shell, (char *) 0);
	return (0);
}
