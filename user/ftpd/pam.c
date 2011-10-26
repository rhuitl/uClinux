#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "extern.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifndef PAM_CONV_AGAIN
# define PAM_CONV_AGAIN PAM_TRY_AGAIN
#endif
#ifndef PAM_INCOMPLETE
# define PAM_INCOMPLETE PAM_TRY_AGAIN
#endif

#ifdef WITH_PAM

static int PAM_conv __P ((int num_msg, const struct pam_message **msg,
			  struct pam_response **resp, void *appdata_ptr));

/* FIXME: We still have a side effect since we use the global variable
   cred.  A better approach would be to use the pcred parameter
   in pam_user().  */
static struct pam_conv PAM_conversation = { &PAM_conv, &cred };

/* PAM authentication, now using the PAM's async feature.  */
static pam_handle_t *pamh;

static int
PAM_conv (int num_msg, const struct pam_message **msg,
	  struct pam_response **resp, void *appdata_ptr)
{
  struct pam_response *repl = NULL;
  int retval, count = 0, replies = 0;
  int size = sizeof(struct pam_response);
  struct credentials *pcred = (struct credentials *) appdata_ptr;

#define GET_MEM \
        if (!(repl = realloc (repl, size))) \
                return PAM_CONV_ERR; \
        size += sizeof (struct pam_response)

  retval = PAM_SUCCESS;

  for (count = 0; count < num_msg; count++)
    {
      int savemsg = 0;

      switch (msg[count]->msg_style)
	{
	case PAM_PROMPT_ECHO_ON:
	  GET_MEM;
	  repl[replies].resp_retcode = PAM_SUCCESS;
	  repl[replies].resp = sgetsave (pcred->name);
	  replies++;
	  break;
	case PAM_PROMPT_ECHO_OFF:
	  GET_MEM;
	  if (pcred->pass == 0)
	    {
	      savemsg = 1;
	      retval = PAM_CONV_AGAIN;
	    }
	  else
	    {
	      repl[replies].resp_retcode = PAM_SUCCESS;
	      repl[replies].resp = sgetsave (pcred->pass);
	      replies++;
	    }
	  break;
	case PAM_TEXT_INFO:
	  savemsg = 1;
	  break;
	case PAM_ERROR_MSG:
	default:
	  /* Must be an error of some sort... */
	  savemsg = 1;
	  retval = PAM_CONV_ERR;
	}

      if (savemsg)
	{
	  /* FIXME:  This is a serious problem.  If the PAM message
	     is multilines, the reply _must_ be formated correctly.
	     The way to do this would be to consider \n as a boundary then
	     in the ftpd.c:user() or ftpd.c:pass() check for it and send
	     a lreply().  But I'm not sure the RFCs allow mutilines replies
	     for a passwd challenge.  Many clients will simply break.  */
	  if (pcred->message) /* XXX: make sure we split newlines correctly */
	    {
	      size_t len = strlen (pcred->message);
	      char *s = realloc (pcred->message, len
				 + strlen (msg[count]->msg) + 1);
	      if (s == NULL)
		{
		  free (pcred->message);
		  pcred->message = NULL;
		}
	      else
		{
		  pcred->message = s;
		  strcat (pcred->message, msg[count]->msg);
		}
	    }
	  else
	    pcred->message = sgetsave (msg[count]->msg);

	  if (pcred->message == NULL)
	    retval = PAM_CONV_ERR;
	  else
	    {
	      char *sp;
	      /* FIXME:  What's this for ? */
	      /* Remove trailing `: ' */
	      sp = pcred->message + strlen (pcred->message);
	      while (sp > pcred->message && strchr (" \t\n:", *--sp))
		*sp = '\0';
	    }
	}

      /* In case of error, drop responses and return */
      if (retval)
	{
	  /* FIXME: drop_reply is not standard, need to clean this.  */
	  //_pam_drop_reply (repl, replies);
	  free (repl);
	  return retval;
	}
    }
  if (repl)
    *resp = repl;
  return PAM_SUCCESS;
}

/* Non-zero means failure. */
static int
pam_doit (struct credentials *pcred)
{
  char *username;
  int error;

  error = pam_authenticate (pamh, 0);

  /* Probably being call for the passwd.  */
  if (error == PAM_CONV_AGAIN || error == PAM_INCOMPLETE)
    {
      /* Avoid overly terse passwd messages and let the people
	 upstairs do something sane.  */
      if (pcred->message && !strcasecmp (pcred->message, "password"))
	{
	  free (pcred->message);
	  pcred->message = NULL;
	}
      return 0;
    }

  if (error == PAM_SUCCESS) /* Alright, we got it */
    {
      error = pam_acct_mgmt (pamh, 0);
      if (error == PAM_SUCCESS)
	error = pam_setcred (pamh, PAM_ESTABLISH_CRED);
      if (error == PAM_SUCCESS)
	error = pam_get_item (pamh, PAM_USER, (const void **) &username);
      if (error == PAM_SUCCESS)
	{
	  if (sgetcred (username, pcred) != 0)
	    error = PAM_AUTH_ERR;
	  else
	    {
	      if (strcasecmp (username, "ftp") == 0)
		pcred->guest = 1;
	    }
	}
    }
  pam_end(pamh, error);
  pamh = 0;

  return (error != PAM_SUCCESS);
}

/* Non-zero return means failure. */
int
pam_user (const char *username, struct credentials *pcred)
{
  int error;

  if (pamh != 0)
    {
      pam_end (pamh, PAM_ABORT);
      pamh = 0;
    }

  if (pcred->name)
    free (pcred->name);
  pcred->name = strdup (username);
  if (pcred->message)
    free (pcred->message);
  pcred->message = NULL;

  error = pam_start ("ftp", pcred->name, &PAM_conversation, &pamh);
  if (error == PAM_SUCCESS)
    error = pam_set_item (pamh, PAM_RHOST, pcred->remotehost);
  if (error != PAM_SUCCESS)
    {
      pam_end (pamh, error);
      pamh = 0;
    }

  if (pamh)
    error = pam_doit (pcred);

  return (error != PAM_SUCCESS);
}

/* Nonzero value return for error.  */
int
pam_pass (const char *passwd, struct credentials *pcred)
{
  int error = PAM_AUTH_ERR;
  if (pamh)
    {
      pcred->pass = passwd;
      error = pam_doit (pcred);
      pcred->pass = NULL;
    }
  return  error != PAM_SUCCESS;
}

#endif /* WITH_PAM */
