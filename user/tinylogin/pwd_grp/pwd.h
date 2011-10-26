#ifndef	__TLG_PWD_H
#define	__TLG_PWD_H

#if defined USE_SYSTEM_PWD_GRP
#include <pwd.h>
#define tlg_setpwent setpwent
#define tlg_endpwent endpwent
#define tlg_getpwent getpwent
#define tlg_putpwent putpwent
#define tlg_getpw getpw
#define tlg_fgetpwent fgetpwent
#define tlg_getpwuid getpwuid
#define tlg_getpwnam getpwnam
#define __tlg_getpwent __tlg_getpwent
#else


#include <sys/types.h>
#include <features.h>
#include <stdio.h>

/* The passwd structure.  */
struct passwd
{
  char *pw_name;		/* Username.  */
  char *pw_passwd;		/* Password.  */
  uid_t pw_uid;			/* User ID.  */
  gid_t pw_gid;			/* Group ID.  */
  char *pw_gecos;		/* Real name.  */
  char *pw_dir;			/* Home directory.  */
  char *pw_shell;		/* Shell program.  */
};

extern void tlg_setpwent __P ((void));
extern void tlg_endpwent __P ((void));
extern struct passwd * tlg_getpwent __P ((void));

extern int tlg_putpwent __P ((__const struct passwd * __p, FILE * __f));
extern int tlg_getpw __P ((uid_t uid, char *buf));

extern struct passwd * tlg_fgetpwent __P ((FILE * file));

extern struct passwd * tlg_getpwuid __P ((__const uid_t));
extern struct passwd * tlg_getpwnam __P ((__const char *));

extern struct passwd * __tlg_getpwent __P ((__const int passwd_fd));

#endif /* USE_SYSTEM_PWD_GRP */
#endif /* pwd.h  */

