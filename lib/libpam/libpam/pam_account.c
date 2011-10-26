/* pam_account.c - PAM Account Management */

#include "pam_private.h"

#include <stdio.h>

int pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
    int retval;

    D(("called"));

    IF_NO_PAMH("pam_acct_mgmt", pamh, PAM_SYSTEM_ERR);

    if (__PAM_FROM_MODULE(pamh)) {
	D(("called from module!?"));
	return PAM_SYSTEM_ERR;
    }

    retval = _pam_dispatch(pamh, flags, PAM_ACCOUNT);

#if HAVE_LIBAUDIT
    retval = _pam_auditlog(pamh, PAM_ACCOUNT, retval, flags);
#endif

#ifdef PAM_STATS
	if (retval != PAM_SUCCESS) {
		
        char usr[MAX_PAM_STATS_USR_SIZE];
		char buf[MAX_PAM_STATS_BUF_SIZE];

		usr[MAX_PAM_STATS_USR_SIZE-1]='\0';
		strncpy(usr,(retval == PAM_USER_UNKNOWN)?"unknown":pamh->user,
				MAX_PAM_STATS_USR_SIZE-1);
		memset(buf,'\0',MAX_PAM_STATS_BUF_SIZE);
		
		snprintf(buf, MAX_PAM_STATS_BUF_SIZE-1,
				"statsd -a incr pam_failed_%s %s \\;"
				         " push pam_last_failure_%s %s \"%s\" 0 \\;"
				         " incr pam_users %s \\;"
				         " incr pam_services %s",
				usr, pamh->service_name,
				usr, pamh->service_name, pam_strerror(pamh, retval),
				usr,
				pamh->service_name);
		
		if (system(buf) == -1) {
			pam_syslog(pamh, LOG_INFO, "%s - failed", buf);
		}
	}
#endif

    return retval;
}
