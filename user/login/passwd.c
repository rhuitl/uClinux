/*****************************************************************************/

/*
 *	passwd.c -- simple change password program.
 *
 *	(C) Copyright 1999, Nick Brok (nick@nbrok.iaehv.nl).
 */

/*****************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pwd.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#ifndef __UC_LIBC__
#include <crypt.h>
#endif
#ifdef CONFIG_USER_OLD_PASSWORDS
#include <crypt_old.h>
#endif
#ifdef EMBED
#include <config/autoconf.h>
#endif
#include <sys/types.h>


/*****************************************************************************/

char *version = "v1.0.3";

#if defined(CONFIG_USER_FLATFSD_FLATFSD)
#define WORK_DIR	"/etc/config/"
#else
#define WORK_DIR	"/var/"
#endif
#define	PASSWDFILE	WORK_DIR "passwd"

#define MAX_CONFIG_LINE_SIZE	300

int writeConfig(char *filename, char *keyword, char *value);
int commitChanges();


static int i64c(int i)
{
	if (i <= 0)
		return ('.');
	if (i == 1)
		return ('/');
	if (i >= 2 && i < 12)
		return ('0' - 2 + i);
	if (i >= 12 && i < 38)
		return ('A' - 12 + i);
	if (i >= 38 && i < 63)
		return ('a' - 38 + i);
	return ('z');
}

static char *crypt_make_salt()
{
	time_t now;
	static unsigned long x;
	static char result[3];

	time(&now);
	x += now + getpid();
	result[0] = i64c(((x >> 18) ^ (x >> 6)) & 077);
	result[1] = i64c(((x >> 12) ^ x) & 077);
	result[2] = '\0';
	return result;
}


int set_password(const char *user, const char *password) {
	FILE *fto;
	struct passwd *pwp, pws;
	int foundit = 0;
	int isroot;

	unlink("/etc/config/npasswd");
	fto = fopen("/etc/config/npasswd", "w");
	if (fto) {
		for(setpwent(); (pwp = getpwent()) != NULL;) {
			if (strcmp(pwp->pw_name, user) == 0) {
				pwp->pw_passwd = crypt(password, crypt_make_salt());
				foundit = 1;
			}
			putpwent(pwp, fto);
		}
		if (!foundit) {
			isroot = strcmp(user, "root") == 0;
			pws.pw_name = (char *)user;
			pws.pw_passwd = crypt(password, crypt_make_salt());
			pws.pw_uid = isroot?0:65534;
			pws.pw_gid = isroot?0:65534;
			pws.pw_gecos = isroot?"superuser":(char *)user;
			pws.pw_dir = isroot?"/":"/home";
			pws.pw_shell = isroot?"/bin/sh":"/bin/false";
			putpwent(&pws, fto);
		}
		fclose(fto);
		rename("/etc/config/npasswd", "/etc/config/passwd");
	}
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	char	*cryptmode, password2[128], password1[128];

	for(;;) {
		strcpy(password1, getpass("Enter new Unix password: "));
		strcpy(password2, getpass("Re-enter new Unix password: "));
		if (strcmp(password1, password2) == 0) {
			if (-1 == set_password("root", password1))
				printf("Unable to write password file\n");
#ifdef CONFIG_USER_OLD_PASSWORDS
			else if (-1 == writeConfig("/etc/config/config", "passwd",
						crypt_old(password1, crypt_make_salt())))
				printf("Unable to write legacy password\n");
#endif
			else if (-1 == commitChanges())
				printf("Unable to commit new password file\n");
			else
				return 0;
			break;
		} else 
			printf("Password not matched, try again.\n");
	}
	return 1;
}

/*****************************************************************************/

/*
 * writeConfig
 *
 * Write to a config file (filename) a keyword and its value,
 * replacing any previous data for that keyword if it exists.
 * For example:
 * To update the /etc/config files wizard from 1 to 0 you would
 * call:
 *          writeConfig("/etc/config", "wizard", "0");
 *
 * args:    filename - the config file name and path (eg. /etc/config)
 *          keyword - the keywrod to write into the config file
 *                      (eg. wizard)
 *          value - the value for the keyword (eg. 0). If NULL then the
 *                  entry for the keyword is deleted.
 * retn:    0 on success, -1 on failure
 */
int writeConfig(char *filename, char *keyword, char *value) {
    FILE *in;
    FILE *out;
   
    char line_buffer[MAX_CONFIG_LINE_SIZE];
    char tmp[MAX_CONFIG_LINE_SIZE];

    in = fopen(filename, "r");
    out = fopen(WORK_DIR ".ptmp", "w");
   
    if (!out) {
        if(in)
            fclose(in);
        return -1;
    }
   
    while(in && (fgets(line_buffer, MAX_CONFIG_LINE_SIZE -1, in)) != NULL) {
        if(sscanf(line_buffer, "%s", tmp) > 0) {
            if(strcmp(tmp, keyword))
                fputs(line_buffer, out);
        }
    }
   
    if(in)
        fclose(in);

    if (value != NULL) {
        sprintf(tmp, "%s %s\n", keyword, value);
        fputs(tmp, out);
    }

    if (fclose(out) != 0)
        return -1;

    rename(WORK_DIR ".ptmp", filename);

    return 0;
}


int
commitChanges()
{
#ifdef CONFIG_USER_FLATFSD_FLATFSD
	if (system("exec flatfsd -s") == -1)
		return -1;
#endif
	return 0;
}

