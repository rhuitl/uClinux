#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include "crypt.h"
#include <string.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif
#ifdef TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  ifdef HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#include "extern.h"


/* If name is "ftp" or "anonymous", the name is not in
   PATH_FTPUSERS, and ftp account exists, set cred, then just return.
   If account doesn't exist, ask for passwd anyway.  Otherwise, check user
   requesting login privileges.  Disallow anyone who does not have a standard
   shell as returned by getusershell().  Disallow anyone mentioned in the file
   PATH_FTPUSERS to allow people such as root and uucp to be avoided.  */

int
auth_user (const char *name, struct credentials *pcred)
{

  pcred->guest = 0;

  switch (pcred->auth_type)
    {
#ifdef WITH_PAM
    case AUTH_TYPE_PAM:
      return pam_user (name, pcred);
#endif
#ifdef WITH_KERBEROS
    case AUTH_TYPE_KERBEROS:
      return -1;
#endif
#ifdef WITH_KERBEROS5
    case AUTH_TYPE_KERBEROS5:
      return -1;
#endif
#ifdef WITH_OPIE
    case AUTH_TYPE_OPIE:
      return -1;
#endif
    case AUTH_TYPE_PASSWD:
    default:
      {
	size_t len;
	if (pcred->message)
	  free (pcred->message);
	len = 64 + strlen (name);
	pcred->message = malloc (len);
	if (pcred->message == NULL)
	  return -1;

	/* check for anonymous logging */
	if (strcmp (name, "ftp") == 0
	    || strcmp (name, "anonymous") == 0)
	  {
	    int err = 0;
	    if (checkuser (PATH_FTPUSERS , "ftp")
		|| checkuser (PATH_FTPUSERS, "anonymous"))
	      {
		snprintf (pcred->message, len, "User %s access denied.", name);
		err = 1;
	      }
	    else if (sgetcred ("ftp", pcred) == 0)
	      {
		pcred->guest = 1;
		strcpy (pcred->message,
			"Guest login ok, type your name as password.");
	      }
	    else
	      {
		snprintf (pcred->message, len, "User %s unknown.", name);
		err = 1;
	      }
	    return err;
	  }

	if (sgetcred (name, pcred) == 0)
	  {
	    const char *cp;
	    const char *shell;

#ifdef HAVE_GETUSERSHELL
	    /* Check if the shell is allowed */
	    shell = pcred->shell;
	    if (shell == NULL || *shell == 0)
	      shell = PATH_BSHELL;
	    setusershell ();
	    while ((cp = getusershell ()) != NULL)
	      if (strcmp (cp, shell) == 0)
		break;
	    endusershell ();
#else
	    cp = "/bin/sh";
#endif

	    if (cp == NULL || checkuser (PATH_FTPUSERS, name))
	      {
		sprintf (pcred->message, "User %s access denied.", name);
		return 1;
	      }
	  }
	else
	  return 1;
	pcred->dochroot = checkuser(PATH_FTPCHROOT, pcred->name);
	snprintf (pcred->message, len,
		  "Password required for %s.", pcred->name);
	return 0;
      }
    } /* swithch (auth_type) */
  return -1;
}

int
auth_pass (const char *passwd, struct credentials *pcred)
{
  switch (pcred->auth_type)
    {
#ifdef WITH_PAM
    case AUTH_TYPE_PAM:
      return pam_pass (passwd, pcred);
#endif
#ifdef WITH_KERBEROS
    case AUTH_TYPE_KERBEROS:
      return -1;
#endif
#ifdef WITH_KERBEROS5
    case AUTH_TYPE_KERBEROS5:
      return -1;
#endif
#ifdef WITH_OPIE
    case AUTH_TYPE_OPIE:
      return -1;
#endif
    case AUTH_TYPE_PASSWD:
    default:
      {
	char *xpasswd;
	char *salt = pcred->passwd;
	/* Try to authenticate the user.  */
	if (pcred->passwd == NULL || *pcred->passwd == '\0')
	  return 1; /* Failed. */
	xpasswd = CRYPT (passwd, salt);
	return  (!xpasswd || strcmp (xpasswd, pcred->passwd) != 0);
      }
    } /* switch (auth_type) */
  return -1;
}

int
sgetcred (const char *name, struct credentials *pcred)
{
  struct passwd *p;

  p = getpwnam (name);
  if (p == NULL)
    return 1;

  if (pcred->name)
    free (pcred->name);
  if (pcred->passwd)
    free (pcred->passwd);
  if (pcred->homedir)
    free (pcred->homedir);
  if (pcred->rootdir)
    free (pcred->rootdir);
  if (pcred->shell)
    free (pcred->shell);

#if defined(HAVE_GETSPNAM) && defined(HAVE_SHADOW_H)
  if (p->pw_passwd == NULL || strlen (p->pw_passwd) == 1)
    {
      struct  spwd *spw;

      setspent ();
      spw = getspnam (p->pw_name);
      if (spw != NULL)
	{
	  time_t now;
	  long today;
	  now = time ((time_t *) 0);
	  today = now / (60 * 60 * 24);
	  if ((spw->sp_expire > 0 && spw->sp_expire < today)
	      || (spw->sp_max > 0 && spw->sp_lstchg > 0
		  && (spw->sp_lstchg + spw->sp_max < today)))
	    {
	      /*reply (530, "Login expired."); */
	      p->pw_passwd = NULL;
	    }
	  else
	    p->pw_passwd = spw->sp_pwdp;
	}
      endspent ();
    }
#endif
  pcred->uid = p->pw_uid;
  pcred->gid = p->pw_gid;
  pcred->name = sgetsave (p->pw_name);
  pcred->passwd = sgetsave (p->pw_passwd);
  pcred->rootdir = sgetsave (p->pw_dir);
  pcred->homedir = sgetsave ("/");
  pcred->shell = sgetsave (p->pw_shell);

  return 0;
}
