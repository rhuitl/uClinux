/*****************************************************************************/

/*
 *	login.c -- simple login program.
 *
 *	(C) Copyright 1999-2001, Greg Ungerer (gerg@snapgear.com).
 * 	(C) Copyright 2001, SnapGear Inc. (www.snapgear.com) 
 * 	(C) Copyright 2000, Lineo Inc. (www.lineo.com) 
 *
 *	Made some changes and additions Nick Brok (nick@nbrok.iaehv.nl).
 */

/*****************************************************************************/

/* Make sure we get the gnu version of basename */
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <config/autoconf.h>
#ifndef __UC_LIBC__
#include <crypt.h>
#endif
#ifdef CONFIG_USER_OLD_PASSWORDS
#include <crypt_old.h>
#endif
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>


#ifdef SECURITY_COUNTS
#include "logcnt.c"
#endif

/*****************************************************************************/

/* Delay bad password exit.
 * 
 * This doesn't really accomplish anything I guess..
 * as other connections can be made in the meantime.. and
 * someone attempting a brute force attack could kill their
 * connection if a delay is detected etc.
 *
 * -m2 (20000201)
 */
#define DELAY_EXIT	1

/*****************************************************************************/

char *version = "v1.0.2";

char usernamebuf[128];

/*****************************************************************************/

/*****************************************************************************/

int main(int argc, char *argv[])
{
	char	*user;
	char	*realpwd, *gotpwd, *cpwd;
	char *host = NULL;
	int flag;
	struct passwd *pwp;

    while ((flag = getopt(argc, argv, "h:")) != EOF) {
        switch (flag) {
        case 'h':
            host = optarg;
            break;
        default:
			fprintf(stderr,
			"login [OPTION]... [username]\n"
			"\nBegin a new session on the system\n\n"
			"Options:\n"
			"\t-h\t\tName of the remote host for this login.\n"
			);
        }
    }

	chdir("/");

	if (optind < argc) {
		user = argv[optind];
	} else {
		printf("login: ");
		fflush(stdout);
		if (fgets(usernamebuf, sizeof(usernamebuf), stdin) == NULL)
			exit(0);
		if ((user = strchr(usernamebuf, '\n')) != 0) {
			*user = '\0';
		}
		user = &usernamebuf[0];
	}

	gotpwd = getpass("Password: ");
	openlog("login", LOG_PID, LOG_AUTHPRIV);
	pwp = getpwnam(user);
	if (gotpwd && pwp
#ifdef ONLY_ALLOW_ROOT
			&& strcmp(user, "root") == 0
#endif
#ifdef SECURITY_COUNTS
			&& access__permitted(user)
#endif
			) {
		int good = 0;


		cpwd = crypt(gotpwd, pwp->pw_passwd);
		if (strcmp(cpwd, pwp->pw_passwd) == 0) 
			good++;

#ifdef CONFIG_USER_OLD_PASSWORDS
		cpwd = crypt_old(gotpwd, pwp->pw_passwd);
		if (strcmp(cpwd, pwp->pw_passwd) == 0)
			good++;
#endif

#ifdef SECURITY_COUNTS
		access__attempted(!good, user);
#endif
		if (good) {
			char arg0[100];

			snprintf(arg0, sizeof(arg0), "-%s", basename(pwp->pw_shell));

			syslog(LOG_INFO, "Authentication successful for %s from %s\n",
					user, host ? host : "unknown");

			execlp(pwp->pw_shell, arg0, NULL);
		} else {
			syslog(LOG_ERR, "Authentication attempt failed for %s from %s because: Bad Password\n",
					user, host ? host : "unknown");
			sleep(DELAY_EXIT);
		}
	} else {
#ifdef SECURITY_COUNTS
		access__attempted(1, user);
#endif
		syslog(LOG_ERR, "Authentication attempt failed for %s from %s because: Invalid Username\n",
					user, host ? host : "unknown");
		sleep(DELAY_EXIT);
	}

	return(0);
}

/*****************************************************************************/
