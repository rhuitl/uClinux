#ifndef	__THG_GRP_H
#define	__THG_GRP_H

#if defined USE_SYSTEM_PWD_GRP
#include <grp.h>
#define tlg_setgrent setgrent
#define tlg_endgrent endgrent
#define tlg_getgrent getgrent
#define tlg_getgrgid getgrgid
#define tlg_getgrnam getgrnam
#define tlg_fgetgrent fgetgrent
#define tlg_setgroups setgroups
#define tlg_initgroups initgroups
#define __tlg_getgrent __getgrent
#else

#include <sys/types.h>
#include <features.h>
#include <stdio.h>

/* The group structure */
struct group
{
  char *gr_name;		/* Group name.	*/
  char *gr_passwd;		/* Password.	*/
  gid_t gr_gid;			/* Group ID.	*/
  char **gr_mem;		/* Member list.	*/
};

extern void tlg_setgrent __P ((void));
extern void tlg_endgrent __P ((void));
extern struct group * tlg_getgrent __P ((void));

extern struct group * tlg_getgrgid __P ((__const gid_t gid));
extern struct group * tlg_getgrnam __P ((__const char * name));

extern struct group * tlg_fgetgrent __P ((FILE * file));

extern int tlg_setgroups __P ((size_t n, __const gid_t * groups));
extern int tlg_initgroups __P ((__const char * user, gid_t gid));

extern struct group * __tlg_getgrent __P ((int grp_fd));

#endif /* USE_SYSTEM_PWD_GRP */
#endif /* _GRP_H */

