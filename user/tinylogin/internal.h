/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Based in part on code from sash, Copyright (c) 1999 by David I. Bell 
 * Permission has been granted to redistribute this code under the GPL.
 *
 */
#ifndef	_INTERNAL_H_
#define	_INTERNAL_H_

#include <config/autoconf.h>

#include "tinylogin.def.h"
#include <pwd.h>
#include <grp.h>
#include <utmp.h>
#include "shadow_.h"

struct Applet {
	const char *name;
	int (*main) (int argc, char **argv);
};

/* Some useful definitions */
#define FALSE   ((int) 1)
#define TRUE    ((int) 0)
#define FAIL_DELAY 3
#define TIMEOUT 60
#define NOLOGIN_FILE	    "/etc/nologin"
#ifndef CONFIG_USER_FLATFSD_FLATFSD
#define PASSWD_FILE	    "/etc/passwd"
#define GROUP_FILE	    "/etc/group"
#else
#define PASSWD_FILE	    "/etc/config/passwd"
#define GROUP_FILE	    "/etc/config/group"
#endif
#define _PATH_LOGIN	    "/bin/login"



/* Main app routines */
extern int tinylogin_main(int argc, char **argv);
extern int adduser_main(int argc, char **argv);
extern int addgroup_main(int argc, char **argv);
extern int deluser_main(int argc, char **argv);
extern int delgroup_main(int argc, char **argv);
extern int login_main(int argc, char **argv);
extern int passwd_main(int argc, char **argv);
extern int su_main(int argc, char **argv);
extern int sulogin_main(int argc, char **argv);
extern int getty_main(int argc, char **argv);

/* Utility routines */
extern void usage(const char *usage);
extern char *pw_encrypt(const char *clear, const char *salt);
extern void updwtmp(const char *filename, const struct utmp *ut);


extern void addenv(const char *string, const char *value);
extern char *xmalloc(size_t size);
extern char *xstrdup(const char *str);
extern void initenv();
extern void checkutmp(int picky);
extern void updwtmp(const char *filename, const struct utmp *ut);
extern void set_env(int argc, char *const *argv);
extern void setutmp(const char *name, const char *line);
extern void setup_env(struct passwd *info);
extern void shell(char *file, char *arg);
extern struct passwd *get_my_pwent(void);
extern struct spwd *pwd_to_spwd(const struct passwd *pw);
extern int update_passwd(const struct passwd *pw, char *crypt_pw);
extern int obscure(const char *old, const char *new,

				   const struct passwd *pwdp);


extern struct utmp utent;


#define STRFCPY(A,B) \
        (strncpy((A), (B), sizeof(A) - 1), (A)[sizeof(A) - 1] = '\0')



#endif							/* _INTERNAL_H_ */
