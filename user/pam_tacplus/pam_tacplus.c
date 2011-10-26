/* pam_tacplus.c	PAM interface for TACACS+ protocol.
 * 
 * Copyright 1998,1999,2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See end of this file for copyright information.
 * See file `CHANGES' for revision history.
 */

#include <stdlib.h>		/* malloc */
#include <syslog.h>
#include <netdb.h>		/* gethostbyname */
#include <sys/socket.h>		/* in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>		/* va_ */
#include <signal.h>
#include <string.h> /* strdup */
#include <unistd.h>

#include "tacplus.h"
#include "libtac.h"
#include "pam_tacplus.h"
#include "support.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
/* #define PAM_SM_PASSWORD */

#include <security/pam_modules.h>

/* support.c */
extern u_long tac_srv[TAC_MAX_SERVERS];
extern int tac_srv_no;
extern char *tac_service;
extern char *tac_protocol;
extern int _pam_parse (int argc, const char **argv);
extern unsigned long _getserveraddr (char *serv);
extern int tacacs_get_password (pam_handle_t * pamh, int flags
		     ,int ctrl, char **password);
extern int converse (pam_handle_t * pamh, int nargs
	  ,struct pam_message **message
	  ,struct pam_response **response);
extern void _pam_log (int err, const char *format,...);
extern void *_xcalloc (size_t size);

/* libtac */
extern char *tac_secret;
extern int tac_encryption;

/* address of server discovered by pam_sm_authenticate */
static u_long active_server = 0;
/* accounting task identifier */
static short int task_id = 0;

/* authenticates user on remote TACACS+ server
 * returns PAM_SUCCESS if the supplied username and password
 * pair is valid 
 */
PAM_EXTERN 
pam_sm_authenticate (pam_handle_t * pamh, int flags,
		     int argc, const char **argv)
{
  int ctrl, retval;
  const char *user;
  char *pass;
  char *tty;
  int srv_i;
  int tac_fd;
  int status = PAM_AUTH_ERR;

  user = pass = tty = NULL;

  ctrl = _pam_parse (argc, argv);

  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
	, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

  retval = pam_get_user (pamh, &user, "Username: ");
  if (retval != PAM_SUCCESS || user == NULL || *user == '\0')
    {
      _pam_log (LOG_ERR, "unable to obtain username");
      return PAM_USER_UNKNOWN;
    }

  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: user [%s] obtained", __FUNCTION__, user);
  
  /* set username */
  /*
  retval = pam_set_item(pamh, PAM_USER, user);
  if(retval != PAM_SUCCESS) {
	  _pam_log(LOG_ERR, "unable to set username item");
	  return PAM_AUTHINFO_UNAVAIL;
  }
  */

  /*
  retval = pam_get_item (pamh, PAM_USER, (const void **) &user);
  if(retval != PAM_SUCCESS) {
	  _pam_log(LOG_ERR, "unable to re-retrieve username item");
	  return PAM_AUTHINFO_UNAVAIL;
  }
  */

  /* XXX uwzgledniac PAM_DISALLOW_NULL_AUTHTOK */

  retval = tacacs_get_password (pamh, flags, ctrl, &pass);
  if (retval != PAM_SUCCESS || pass == NULL || *pass == '\0')
    {
      _pam_log (LOG_ERR, "unable to obtain password");
      return PAM_CRED_INSUFFICIENT;
    }

  retval = pam_set_item (pamh, PAM_AUTHTOK, pass);
  if (retval != PAM_SUCCESS)
    {
      _pam_log (LOG_ERR, "unable to set password");
      return PAM_CRED_INSUFFICIENT;
    }

  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: pass [%s] obtained", __FUNCTION__, pass);

  tty = _pam_get_terminal(pamh);

  if (!strncmp (tty, "/dev/", 5))
    {
      tty += 5;
    }

  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

  for (srv_i = 0; srv_i < tac_srv_no; srv_i++)
    {
      char *msg = NULL;
  	  if (ctrl & PAM_TAC_DEBUG)
			  syslog (LOG_DEBUG, "%s: trying srv %d",
							  __FUNCTION__, srv_i );
      tac_fd = tac_connect_single(tac_srv[srv_i]);
      if (tac_fd < 0)
	{
	  _pam_log (LOG_ERR, "connection failed srv %d: %m", srv_i);
	  if (srv_i == tac_srv_no-1) /* XXX check if OK */
	    {			/* last server tried */
	      _pam_log (LOG_ERR, "no more servers to connect");
	      return PAM_AUTHINFO_UNAVAIL;
	    }
	}
      if (tac_authen_pap_send (tac_fd, user, pass, tty) < 0)
	{
	  _pam_log (LOG_ERR, "error sending auth req to TACACS+ server");
	  status = PAM_AUTHINFO_UNAVAIL;
	}
      else
	{
	  msg = tac_authen_pap_read (tac_fd);
	  if (msg != NULL)
	    {
	      _pam_log (LOG_ERR, "auth failed: %s", msg);
	      status = PAM_AUTH_ERR;
	    }
	  else {
	    /* OK, we got authenticated; save the server that
	       accepted us for pam_sm_acct_mgmt and exit the loop */
	    status = PAM_SUCCESS;
	    active_server = tac_srv[srv_i];
	    close(tac_fd);
	    break;
	  }
	}
      close(tac_fd);
      /* if we are here, this means that authentication failed
	 on current server; break if we are not allowed to probe
	 another one, continue otherwise */
      if (!ctrl & PAM_TAC_FIRSTHIT)
	break;
    }
  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: exit", __FUNCTION__);
  bzero (pass, strlen (pass));
  free(pass);
  pass = NULL;
  return status;

}				/* pam_sm_authenticate */

/* no-op function to satisfy PAM authentication module */ 
PAM_EXTERN 
pam_sm_setcred (pam_handle_t * pamh, int flags,
		int argc, const char **argv)
{
  int ctrl = _pam_parse (argc, argv);

  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
	, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

  return PAM_SUCCESS;
}				/* pam_sm_setcred */

/* authorizes user on remote TACACS+ server, i.e. checks
 * his permission to access requested service
 * returns PAM_SUCCESS if the service is allowed
 */
PAM_EXTERN 
pam_sm_acct_mgmt (pam_handle_t * pamh, int flags,
		  int argc, const char **argv)
{
  int retval, ctrl, status=PAM_AUTH_ERR;
  char *user;
  char *tty;
  struct areply arep;
  struct tac_attrib *attr = NULL;
  int tac_fd;
  char *rhostname;
  u_long rhost = 0;

  user = tty = rhostname = NULL;
  
  /* this also obtains service name for authorization
     this should be normally performed by pam_get_item(PAM_SERVICE)
     but since PAM service names are incompatible TACACS+
     we have to pass it via command line argument until a better
     solution is found ;) */
  ctrl = _pam_parse (argc, argv);

  if (ctrl & PAM_TAC_DEBUG) {
    struct in_addr addr;

    syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
	, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

    bcopy(&active_server, &addr.s_addr, sizeof(addr.s_addr)); 
    syslog (LOG_DEBUG, "%s: active server is [%s]", __FUNCTION__,
		    inet_ntoa(addr));
  }
  
  retval = pam_get_item(pamh, PAM_USER, (const void **) &user);
  if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
      _pam_log (LOG_ERR, "unable to obtain username");
      return PAM_USER_UNKNOWN;
    }

  if (ctrl & PAM_TAC_DEBUG) {
	  syslog(LOG_DEBUG, "%s: username obtained [%s]", __FUNCTION__, user);
  }
  
  tty = _pam_get_terminal(pamh);

  if(!strncmp(tty, "/dev/", 5)) 
	  tty += 5;

  if (ctrl & PAM_TAC_DEBUG) {
	  syslog(LOG_DEBUG, "%s: tty obtained [%s]", __FUNCTION__, tty);
  }
  
  /* XXX temporarily disabled 
  retval = pam_get_item(pamh, PAM_RHOST, (const void **) &rhostname);
  */
  /* if this fails, this means the remote host name was not supplied
     by the application, and there's no need to report error; if it was,
     then we appreciate this :) */
  /* XXX this is lame */
  /*
  if(retval == PAM_SUCCESS && rhostname != NULL && *rhostname != '\0') {
	  rhost = _resolve_name(rhostname);
	  rhostname = NULL;
   */
	  /* if _resolve_name succeded, rhost now contains IP address
	     in binary form, rhostname is prepared for storing its
	     ASCII representation */
  /*
  	  if (ctrl & PAM_TAC_DEBUG) {
	  	syslog(LOG_DEBUG, "%s: rhost obtained [%lx]", __FUNCTION__,
				rhost);
  	  }
  }
  */
  
  /* checks if user has been successfully authenticated
     by TACACS+; we cannot solely authorize user if it hasn't
     been authenticated or has been authenticated by method other
     than TACACS+ */
  if(!active_server) {
	  _pam_log (LOG_ERR, "user not authenticated by TACACS+");
	  return PAM_AUTH_ERR;
  }

  /* checks for specific data required by TACACS+, which should
     be supplied in command line  */
  if(tac_service == NULL || *tac_service == '\0') {
	  _pam_log (LOG_ERR, "TACACS+ service type not configured");
	  return PAM_AUTH_ERR;
  }
  if(tac_protocol == NULL || *tac_protocol == '\0') {
	  _pam_log (LOG_ERR, "TACACS+ protocol type not configured");
	  return PAM_AUTH_ERR;
  }

  tac_add_attrib(&attr, "service", tac_service);
  tac_add_attrib(&attr, "protocol", tac_protocol);

  if(rhost) {
	  struct in_addr addr;
	  bcopy(&rhost, &addr.s_addr, sizeof(addr.s_addr));
	  tac_add_attrib(&attr, "ip", inet_ntoa(addr));
  }
  
  tac_fd = tac_connect_single(active_server);
  if(tac_fd < 0) {
	  _pam_log (LOG_ERR, "TACACS+ server unavailable");
	  status = PAM_AUTH_ERR;
	  goto ErrExit;
  }

  retval = tac_author_send(tac_fd, user, tty, attr);
  
  /* this is no longer needed */
  tac_free_attrib(&attr);
  
  if(retval < 0) {
	  _pam_log (LOG_ERR, "error getting authorization");
	  status = PAM_AUTH_ERR;
	  goto ErrExit;
  }

  if (ctrl & PAM_TAC_DEBUG) {
	  syslog(LOG_DEBUG, "%s: sent authorization request", __FUNCTION__);
  }
  
  tac_author_read(tac_fd, &arep);

  if(arep.status != AUTHOR_STATUS_PASS_ADD &&
		  arep.status != AUTHOR_STATUS_PASS_REPL) {
	  _pam_log (LOG_ERR, "TACACS+ authorisation failed for [%s]", user);
	  status = PAM_PERM_DENIED;
	  goto ErrExit;
  }

  if (ctrl & PAM_TAC_DEBUG) {
	  syslog(LOG_DEBUG, "%s: user [%s] successfully authorized", 
			  __FUNCTION__, user);
  }
  
  status = PAM_SUCCESS;
  
  /* set PAM_RHOST if 'addr' attribute was returned from server */
  attr = arep.attr;
  while (attr != NULL)  {
		  if(!strncmp(attr->attr, "addr", 4)) {
			char buff[128];
			char *sep;
			
			sep = index(attr->attr, '=');
			if(sep == NULL)
					sep = index(attr->attr, '*');
			if(sep == NULL) {
					syslog(LOG_WARNING, "%s: invalid attribute `%s', no separator", __FUNCTION__, attr->attr);
					break;
			}
			
			bcopy(++sep, buff, attr->attr_len-5);
			buff[attr->attr_len-5] = '\0';
			
			if(isdigit(*buff)) 
					retval = pam_set_item(pamh, PAM_RHOST, buff);
					if (retval != PAM_SUCCESS)
							syslog(LOG_WARNING, "%s: unable to set remote address for PAM", __FUNCTION__);
					else if(ctrl & PAM_TAC_DEBUG)
							syslog(LOG_DEBUG, "%s: set remote addr to `%s'", __FUNCTION__, buff);
				  
		  	break;
		  }
		  attr = attr->next;
  }

  /* free returned attributes */
  if(arep.attr != NULL) tac_free_attrib(&arep.attr);

ErrExit:
  
  close(tac_fd);

  return status;
}				/* pam_sm_acct_mgmt */

/* sends START accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
/* accounting packets may be directed to any TACACS+ server,
 * independent from those used for authentication and authorization;
 * it may be also directed to all specified servers
 */  
PAM_EXTERN 
pam_sm_open_session (pam_handle_t * pamh, int flags,
		     int argc, const char **argv)
{
		task_id=(short int) magic();
		return(_pam_account(pamh, argc, argv,TAC_PLUS_ACCT_FLAG_START)); 
}				/* pam_sm_open_session */

/* sends STOP accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
PAM_EXTERN 
pam_sm_close_session (pam_handle_t * pamh, int flags,
		      int argc, const char **argv) {
		return(_pam_account(pamh, argc, argv,TAC_PLUS_ACCT_FLAG_STOP)); 

}	/* pam_sm_close_session */

PAM_EXTERN
_pam_account(pam_handle_t *pamh, int argc, const char **argv,  int type)
{
  int retval;
  static int ctrl;
  char *user, *tty, *typemsg;
  int status = PAM_SESSION_ERR;
  
  user = tty = NULL;

  typemsg = (type == TAC_PLUS_ACCT_FLAG_START) ? "START" : "STOP";
  /* debugging
  if(type == TAC_PLUS_ACCT_FLAG_STOP)
		  sleep(60);
		  */
  
  /* when we are sending STOP packet we no longer have uid 0 */
/*  if(type == TAC_PLUS_ACCT_FLAG_START) */
  	ctrl = _pam_parse (argc, argv);

  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: [%s] called (pam_tacplus v%hu.%hu.%hu)"
	, __FUNCTION__, typemsg, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);
  if (ctrl & PAM_TAC_DEBUG)
	  syslog(LOG_DEBUG, "%s: tac_srv_no=%d", __FUNCTION__, tac_srv_no);
  
  retval = pam_get_item(pamh, PAM_USER, (const void **) &user);
  if(retval != PAM_SUCCESS || user == NULL || *user == '\0') {
	  _pam_log(LOG_ERR, "%s: unable to obtain username", __FUNCTION__);
	  return PAM_SESSION_ERR;
  }

  if (ctrl & PAM_TAC_DEBUG)
	  syslog(LOG_DEBUG, "%s: username [%s] obtained", __FUNCTION__, user);
  
  tty = _pam_get_terminal(pamh);
  
  if(!strncmp(tty, "/dev/", 5)) 
	  tty += 5;
  
  if (ctrl & PAM_TAC_DEBUG)
  	syslog(LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

  /* checks for specific data required by TACACS+, which should
     be supplied in command line  */
  if(tac_service == NULL || *tac_service == '\0') {
    _pam_log (LOG_ERR, "TACACS+ service type not configured");
    return PAM_AUTH_ERR;
  }
  if(tac_protocol == NULL || *tac_protocol == '\0') {
    _pam_log (LOG_ERR, "TACACS+ protocol type not configured");
    return PAM_AUTH_ERR;
  }

  /* when this module is called from within pppd or other
	 application dealing with serial lines, it is likely
	 that we will get hit with signal caused by modem hangup;
	 this is important only for STOP packets, it's relatively
	 rare that modem hangs up on accounting start */
  if(type == TAC_PLUS_ACCT_FLAG_STOP) {
  	signal(SIGALRM, SIG_IGN);
  	signal(SIGCHLD, SIG_IGN);
  	signal(SIGHUP, SIG_IGN);
  }

  if(! ctrl & PAM_TAC_ACCT) {
  /* normal mode, send packet to the first available server */
		  int tac_fd;
		  
		  status = PAM_SUCCESS;

		  
		  tac_fd = tac_connect(tac_srv, tac_srv_no);
		  if(tac_fd < 0) {
				  _pam_log(LOG_ERR, "%s: error sending %s - no servers",
								  __FUNCTION__, typemsg);
				  status = PAM_SESSION_ERR;
		  }
  		  if (ctrl & PAM_TAC_DEBUG)
				  syslog(LOG_DEBUG, "%s: connected with fd=%d", __FUNCTION__, tac_fd);

  		  retval = _pam_send_account(tac_fd, type,
						user, tty);
		  if(retval < 0) {
				  _pam_log(LOG_ERR, "%s: error sending %s", 
								  __FUNCTION__, typemsg);
				  status = PAM_SESSION_ERR;
		  }
		  
		  close(tac_fd);
  		  
		  if (ctrl & PAM_TAC_DEBUG) {
				  syslog(LOG_DEBUG, "%s: [%s] for [%s] sent",
								  __FUNCTION__, typemsg,user);
		  }

  } else {
  /* send packet to all servers specified */
		  int srv_i;
		  
		  status = PAM_SESSION_ERR;
		  
		  for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
				  int tac_fd;
				  
				  tac_fd = tac_connect_single(tac_srv[srv_i]);
				  if(tac_fd < 0) {
						  _pam_log(LOG_WARNING, "%s: error sending %s (fd)",
										  __FUNCTION__, typemsg);
						  continue;
				  }

  		  		  if (ctrl & PAM_TAC_DEBUG)
				  	syslog(LOG_DEBUG, "%s: connected with fd=%d (srv %d)", __FUNCTION__, tac_fd, srv_i);


				  retval = _pam_send_account(tac_fd, type,
								  user, tty);

				  
				  /* return code from function in this mode is
					 status of the last server we tried to send
					 packet to */
				  if(retval < 0) 
						  _pam_log(LOG_WARNING, "%s: error sending %s (acct)",
										  __FUNCTION__, typemsg);
				  else {
						  status = PAM_SUCCESS;
		  				  if (ctrl & PAM_TAC_DEBUG) 
				  				  syslog(LOG_DEBUG, "%s: [%s] for [%s] sent",
								  		__FUNCTION__, typemsg,user);
				  }

				  close(tac_fd);

		  }
				  
  }  /* acct mode */

  if(type == TAC_PLUS_ACCT_FLAG_STOP) {
  	signal(SIGALRM, SIG_DFL);
  	signal(SIGCHLD, SIG_DFL);
  	signal(SIGHUP, SIG_DFL);
  }
			  
  return status;
}				

int _pam_send_account(int tac_fd, int type, char *user, char *tty) {
	char buf[40];
	struct tac_attrib *attr;
	int retval, status = -1;
	

	attr=(struct tac_attrib *)_xcalloc(sizeof(struct tac_attrib));
	
	sprintf(buf, "%lu", time(0));
	tac_add_attrib(&attr, 
		(type == TAC_PLUS_ACCT_FLAG_START) ? "start_time" : "stop_time"
			, buf);
	sprintf(buf, "%hu", task_id);
	tac_add_attrib(&attr, "task_id", buf);
	tac_add_attrib(&attr, "service", tac_service);
	tac_add_attrib(&attr, "protocol", tac_protocol);
	/* XXX this requires pppd to give us this data */
	/*
	tac_add_attrib(&attr, "addr", ip_ntoa(ho->hisaddr));
	*/

	retval = tac_account_send(tac_fd, type, user, tty, attr);

	/* this is no longer needed */
	tac_free_attrib(&attr);
	
	if(retval < 0) {
		_pam_log (LOG_WARNING, "%s: send %s accounting failed (task %hu)",
			__FUNCTION__, 
			(type == TAC_PLUS_ACCT_FLAG_START) ? "start" : "stop",
			task_id);
		status = -1;
		goto ErrExit;
	}
	
	if(tac_account_read(tac_fd) != NULL) {
		_pam_log (LOG_WARNING, "%s: accounting %s failed (task %hu)",
			__FUNCTION__, 
			(type == TAC_PLUS_ACCT_FLAG_START) ? "start" : "stop",
			task_id);
		status = -1;
		goto ErrExit;
	}

	status = 0;

ErrExit:
	close(tac_fd);
	return status;
}

#ifdef PAM_SM_PASSWORD
/* no-op function for future use */ 
PAM_EXTERN 
pam_sm_chauthtok (pam_handle_t * pamh, int flags,
		  int argc, const char **argv)
{
  int ctrl = _pam_parse (argc, argv);

  if (ctrl & PAM_TAC_DEBUG)
    syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
	, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

  return PAM_SUCCESS;
}				/* pam_sm_chauthtok */
#endif


#ifdef PAM_STATIC

struct pam_module _pam_tacplus_modstruct
{
  "pam_tacplus",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
#ifdef PAM_SM_PASSWORD
  pam_sm_chauthtok
#else
  NULL
#endif
};
#endif

/*
 * Copyright 1998 by Pawel Krawczyk <kravietz@ceti.com.pl>
 *                                              All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

