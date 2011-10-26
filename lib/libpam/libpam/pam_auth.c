/*
 * pam_auth.c -- PAM authentication
 *
 * $Id: pam_auth.c,v 1.6 2006/01/12 10:06:49 t8m Exp $
 *
 */

#include "pam_private.h"
#include "pam_prelude.h"

#include <stdio.h>
#include <stdlib.h>

int pam_authenticate(pam_handle_t *pamh, int flags)
{
    int retval;

    D(("pam_authenticate called"));

    IF_NO_PAMH("pam_authenticate", pamh, PAM_SYSTEM_ERR);

    if (__PAM_FROM_MODULE(pamh)) {
	D(("called from module!?"));
	return PAM_SYSTEM_ERR;
    }

    if (pamh->former.choice == PAM_NOT_STACKED) {
	_pam_sanitize(pamh);
	_pam_start_timer(pamh);    /* we try to make the time for a failure
				      independent of the time it takes to
				      fail */
    }

    retval = _pam_dispatch(pamh, flags, PAM_AUTHENTICATE);

    if (retval != PAM_INCOMPLETE) {
	_pam_sanitize(pamh);
	_pam_await_timer(pamh, retval);   /* if unsuccessful then wait now */
	D(("pam_authenticate exit"));
    } else {
	D(("will resume when ready"));
    }

#ifdef PRELUDE
    prelude_send_alert(pamh, retval);
#endif

#if HAVE_LIBAUDIT
    retval = _pam_auditlog(pamh, PAM_AUTHENTICATE, retval, flags);
#endif

#ifdef PAM_STATS
	if (retval != PAM_SUCCESS) {

        char usr[MAX_PAM_STATS_USR_SIZE];
		char buf[MAX_PAM_STATS_BUF_SIZE]; 
		struct pam_data *data;
        char *u = NULL;

		/* The pam_sg module has stored module data so we 
		 * can tell whether this is a valid user. If not
		 * we log stats under "unknown". The proper mechanism
		 * for accessing module data bars access from within 
		 * application code so we are going around it. This is 
		 * a kludge, but the best one possible for now.
		 */
		data = pamh->data;
		while (data) {
			if ((!strcmp((data->name)+3, "null")) ||
			    (!strcmp((data->name)+3, pamh->user))) {
				u = (char *)(data->data);
				break;
			}
			data = data->next;
		}

		/* Don't log stats if the module info is unavailable
		 * or the PAM system itself failed during auth */
		if ((u != NULL) && strcmp(u, "PAM_SYSTEM_ERR")) {

			u = (!strcmp(u, "PAM_USER_UNKNOWN")) ? "unknown":pamh->user;

			usr[MAX_PAM_STATS_USR_SIZE-1]='\0';
			strncpy(usr,u,MAX_PAM_STATS_USR_SIZE-1);

			/* OK, start logging stats */
			memset(buf,'\0',MAX_PAM_STATS_BUF_SIZE);

			snprintf(buf, MAX_PAM_STATS_BUF_SIZE-1,
					"statsd -a incr pam_failed_%s %s \\;"
					         " push pam_last_failure_%s %s \"%s\" 0 \\;"
					         " incr pam_users %s \\; incr pam_services %s",
					usr,pamh->service_name,
					usr,pamh->service_name, pam_strerror(pamh, retval),
					usr,
					pamh->service_name);

			if (system(buf) == -1) {
				pam_syslog(pamh, LOG_INFO, "%s - failed", buf);
			}
		} 
	}
#endif

    return retval;
}

int pam_setcred(pam_handle_t *pamh, int flags)
{
    int retval;

    D(("pam_setcred called"));

    IF_NO_PAMH("pam_setcred", pamh, PAM_SYSTEM_ERR);

    if (__PAM_FROM_MODULE(pamh)) {
	D(("called from module!?"));
	return PAM_SYSTEM_ERR;
    }

    if (! flags) {
	flags = PAM_ESTABLISH_CRED;
    }

    retval = _pam_dispatch(pamh, flags, PAM_SETCRED);

#if HAVE_LIBAUDIT
    retval = _pam_auditlog(pamh, PAM_SETCRED, retval, flags);
#endif

    D(("pam_setcred exit"));

    return retval;
}
