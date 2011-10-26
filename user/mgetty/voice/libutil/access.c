/*
 * access.c
 *
 * Functions to switch EUID/EGUID and umask. Warning, there must be
 * exactly one unnested call to voice_desimpersonify() for each
 * voice_impersonify() because of the static umask below.
 *
 * $Id: access.c,v 1.3 2003/04/23 08:49:16 gert Exp $
 *
 */

#include "../include/voice.h"

static int old_umask; /* this is persistant accross calls */

int voice_impersonify(void) {
   uid_t uid;
   gid_t gid;

   /* Switch the UID and the GID. This is the new way of doing things.
    * It avoids races (open()/chown()), and checks correct permissions
    * without races (access()), notably symlink ones.
    * However, this now needs UID or GID write access to the spool
    * (ie directory +w). Note that the file mode should be assured by
    * umask or by permissions on the directory.
    * NB: needs to switch the GUID first.
    */

   get_ugid((char *) &cvd.phone_owner,
	    (char *) &cvd.phone_group,
	    &uid,
	    &gid);

   if (setegid(gid)) {
      lprintf(L_WARN, "%s: cannot set effective GID to %d: %s",
	      program_name, gid, strerror(errno));
      return 0;
   }

   if (seteuid(uid)) {
      lprintf(L_WARN, "%s: cannot set effective UID to %d: %s",
	      program_name, uid, strerror(errno));
      return 0;
   }

   if (cvd.phone_mode.d.i != -1) {
      old_umask = umask(0666 & ~(cvd.phone_mode.d.i));
   }

   return 1; /* succeeded */
}

int voice_desimpersonify(void) {
   if (seteuid(getuid())) {
      lprintf(L_WARN, "%s: cannot switch back to effective UID %d: %s",
	      program_name, getuid(), strerror(errno));
      return 0;
   }

   if (setegid(getgid())) {
      lprintf(L_WARN, "%s: cannot switch back to effective GID %d: %s",
	      program_name, getgid(), strerror(errno));
      return 0;
   }

   if (cvd.phone_mode.d.i != -1) {
      umask(old_umask);
   }

   return 1;
}
