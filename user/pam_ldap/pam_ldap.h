/*
 * Copyright (C) 1998-2004 Luke Howard.
 * This file is part of the pam_ldap library.
 * Contributed by Luke Howard, <lukeh@padl.com>, 1998.
 *
 * The pam_ldap library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The pam_ldap library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the pam_ldap library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MISC_H
#include <security/pam_misc.h>
#elif defined(HAVE_PAM_PAM_MISC_H)
#include <pam/pam_misc.h>
#endif

#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#else
#include <pam/pam_modules.h>
#endif

typedef struct pam_ssd
  {
    char *base;
    int scope;
    char *filter;
    struct pam_ssd *next;
} pam_ssd_t;

/* /etc/ldap.conf nss_ldap-style configuration */
typedef struct pam_ldap_config
  {
    /* file name read from */
    char *configFile;
    /* URI */
    char *uri;
    /* space delimited list of servers */
    char *host;
    /* port, expected to be common to all servers */
    int port;
    /* base DN, eg. dc=gnu,dc=org */
    char *base;
    /* scope for searches */
    int scope;
    /* deref policy */
    int deref;
    /* bind dn/pw for "anonymous" authentication */
    char *binddn;
    char *bindpw;
    /* bind dn/pw for "root" authentication */
    char *rootbinddn;
    char *rootbindpw;
    /* SSL config states */
#define SSL_OFF          0
#define SSL_LDAPS        1
#define SSL_START_TLS    2
    int ssl_on;
    /* SSL path */
    char *sslpath;
    /* list of SSDs to augment defaults */
    pam_ssd_t *ssd;
    /* filter to AND with uid=%s */
    char *filter;
    /* attribute to search on; defaults to uid. Use CN with ADS? */
    char *userattr;
    /* attribute to set PAM_USER based on */
    char *tmplattr;
    /* default template user */
    char *tmpluser;
    /* search for Netscape password policy */
    int getpolicy;
    /* host attribute checking, for access authorization */
    int checkhostattr;
    /* service attribute checking, for access authorization */
    int checkserviceattr;
    /* group name; optional, for access authorization */
    char *groupdn;
    /* group membership attribute; defaults to uniquemember */
    char *groupattr;
    /* LDAP protocol version */
    int version;
    /* search timelimit */
    int timelimit;
    /* bind timelimit */
    int bind_timelimit;
    /* automatically chase referrals */
    int referrals;
    /* restart interrupted syscalls, OpenLDAP only */
    int restart;
    /* chauthtok config states */
#define PASSWORD_CLEAR   0
#define PASSWORD_CRYPT   1
#define PASSWORD_MD5     2
#define PASSWORD_CLEAR_REMOVE_OLD     3
#define PASSWORD_AD      4
#define PASSWORD_EXOP    5
#define PASSWORD_EXOP_SEND_OLD	6
    int password_type;
    /* stop all changes, present message */
    char *password_prohibit_message;
    /* min uid */
    uid_t min_uid;
    /* max uid */
    uid_t max_uid;
    /* tls check peer */
    int tls_checkpeer;
    /* tls ca certificate file */
    char *tls_cacertfile;
    /* tls ca certificate dir */
    char *tls_cacertdir;
    /* tls ciphersuite */
    char *tls_ciphers;
    /* tls certificate */
    char *tls_cert;
    /* tls key */
    char *tls_key;
    /* tls randfile */
    char *tls_randfile;
    /* directory for debug files */
    char *logdir;
    /* ldap debug level */
    int debug;
    /* SASL mechanism */
    char *sasl_mechanism;
  }
pam_ldap_config_t;

/* Netscape global password policy attributes */
typedef struct pam_ldap_password_policy
  {
    int password_change;
    int password_check_syntax;
    int password_min_length;
    int password_exp;
    int password_max_age;
    int password_warning;
    int password_keep_history;
    int password_in_history;
    int password_lockout;
    int password_max_failure;
    int password_unlock;
    int password_lockout_duration;
    int password_reset_duration;
  }
pam_ldap_password_policy_t;

/* Standard Unix style shadow controls */
typedef struct pam_ldap_shadow
  {
    int shadowacct;		/* is shadowAccount */
    long int lstchg;		/* Date of last change.  */
    long int min;		/* Minimum number of days between changes.  */
    long int max;		/* Maximum number of days between changes.  */
    long int warn;		/* Number of days to warn user to change
				   the password.  */
    long int inact;		/* Number of days the account may be
				   inactive.  */
    long int expire;		/* Number of days since 1970-01-01 until
				   account expires.  */
    unsigned long int flag;	/* Reserved.  */
  }
pam_ldap_shadow_t;

/* Password controls sent to client */
#ifndef LDAP_CONTROL_PWEXPIRED
#define LDAP_CONTROL_PWEXPIRED      "2.16.840.1.113730.3.4.4"
#endif /* LDAP_CONTROL_PWEXPIRED */
#ifndef LDAP_CONTROL_PWEXPIRING
#define LDAP_CONTROL_PWEXPIRING     "2.16.840.1.113730.3.4.5"
#endif /* LDAP_CONTROL_PWEXPIRING */
#ifndef LDAP_CONTROL_PASSWORDPOLICYREQUEST
#define LDAP_CONTROL_PASSWORDPOLICYREQUEST	"1.3.6.1.4.1.42.2.27.8.5.1"
#endif /* LDAP_CONTROL_PASSWORDPOLICYREQUEST */
#ifndef LDAP_CONTROL_PASSWORDPOLICYRESPONSE
#define LDAP_CONTROL_PASSWORDPOLICYRESPONSE	"1.3.6.1.4.1.42.2.27.8.5.1"
#endif	/* LDAP_CONTROL_PASSWORDPOLICYRESPONSE */

#define POLICY_WARN_TIME_BEFORE_EXPIRATION		128
#define POLICY_WARN_GRACE_LOGINS_REMAINING		129

#define POLICY_ERROR_SUCCESS				-1
#define POLICY_ERROR_PASSWORD_EXPIRED			0
#define POLICY_ERROR_ACCOUNT_LOCKED			1
#define POLICY_ERROR_CHANGE_AFTER_RESET			2
#define POLICY_ERROR_PASSWORD_MOD_NOT_ALLOWED		3
#define POLICY_ERROR_MUST_SUPPLY_OLD_PASSWORD		4
#define POLICY_ERROR_INSUFFICIENT_PASSWORD_QUALITY	5
#define POLICY_ERROR_PASSWORD_TOO_SHORT			6
#define POLICY_ERROR_PASSWORD_TOO_YOUNG			7
#define POLICY_ERROR_PASSWORD_INSUFFICIENT		8

#ifndef LDAP_OPT_ON
#define LDAP_OPT_ON ((void *) 1)
#endif /* LDAP_OPT_ON */
#ifndef LDAP_OPT_OFF
#define LDAP_OPT_OFF ((void *) 0)
#endif /* LDAP_OPT_OFF */

#if defined(LDAP_EXOP_X_MODIFY_PASSWD) && !defined(LDAP_EXOP_MODIFY_PASSWD)
#define LDAP_EXOP_MODIFY_PASSWD LDAP_EXOP_X_MODIFY_PASSWD
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID
#define LDAP_TAG_EXOP_MODIFY_PASSWD_OLD LDAP_TAG_EXOP_X_MODIFY_PASSWD_OLD
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW
#endif

/* Seconds in a day */
#define SECSPERDAY 86400

/* Netscape per-use password attributes. Unused except for DN. */
typedef struct pam_ldap_user_info
  {
    /* user name, to validate info cache */
    char *username;
    /* DN of user in directory */
    char *userdn;
    /* temporary cache of user's bind credentials for rebind function */
    char *userpw;
    /* host attribute from account objectclass */
    char **hosts_allow;
    char **services_allow;
    /* seconds until password expires */
    long password_expiration_time;
    /* grace logins remaining */
    int grace_logins_remaining;
    /* password policy error */
    int policy_error;
    /* bound as user DN */
    int bound_as_user;
    /* user ID */
    uid_t uid;
    /* mapped user */
    char *tmpluser;
    /* shadow stuff */
    pam_ldap_shadow_t shadow;
  }
pam_ldap_user_info_t;

/*
 * Per PAM-call LDAP session. We keep the user info and
 * LDAP handle cached to minimize binds and searches to
 * the directory, particularly as you can't rebind within
 * a V2 session.
 */
typedef struct pam_ldap_session
  {
    LDAP *ld;
    pam_ldap_config_t *conf;
    pam_ldap_user_info_t *info;
  }
pam_ldap_session_t;

#define OLD_PASSWORD_PROMPT "Enter login(LDAP) password: "
#define NEW_PASSWORD_PROMPT "New password: "
#define AGAIN_PASSWORD_PROMPT "Re-enter new password: "

/* pam_ldap session */
#define PADL_LDAP_SESSION_DATA "PADL-LDAP-SESSION-DATA"
/* expired user */
#define PADL_LDAP_AUTHTOK_DATA "PADL-LDAP-AUTHTOK-DATA"
/* non-template user (pre-mapping) */
#define PADL_LDAP_AUTH_DATA "PADL-LDAP-AUTH-DATA"
/* authtok for Solaris */
#define PADL_LDAP_OLDAUTHTOK_DATA "PADL-LDAP-OLDAUTHTOK-DATA"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef _pam_overwrite
#define _pam_overwrite(x) \
{ \
     register char *__xx__; \
     if ((__xx__=x)) \
          while (*__xx__) \
               *__xx__++ = '\0'; \
}
#endif

#ifndef _pam_drop
#define _pam_drop(X) \
if (X) { \
    free(X); \
    X=NULL; \
}
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ 1024
#endif /* LDAP_FILT_MAXSIZ */

#define IGNORE_UNKNOWN_USER	0x01
#define IGNORE_AUTHINFO_UNAVAIL	0x02

#define STATUS_MAP_IGNORE_POLICY(_rc, _ignore_flags) do { \
	if ((_rc) == PAM_USER_UNKNOWN && ((_ignore_flags) & IGNORE_UNKNOWN_USER)) \
		rc = PAM_IGNORE; \
	else if ((_rc) == PAM_AUTHINFO_UNAVAIL && ((_ignore_flags) & IGNORE_AUTHINFO_UNAVAIL)) \
		rc = PAM_IGNORE; \
	} while (0)

/* PAM authentication routine */
#define PAM_SM_AUTH
PAM_EXTERN int pam_sm_authenticate (pam_handle_t *, int, int, const char **);
PAM_EXTERN int pam_sm_setcred (pam_handle_t *, int, int, const char **);

/* PAM session management */
#define PAM_SM_SESSION
PAM_EXTERN int pam_sm_open_session (pam_handle_t *, int, int, const char **);
PAM_EXTERN int pam_sm_close_session (pam_handle_t *, int, int, const char **);

/* PAM password changing routine */
#define PAM_SM_PASSWORD
PAM_EXTERN int pam_sm_chauthtok (pam_handle_t *, int, int, const char **);

/* PAM authorization routine */
#define PAM_SM_ACCOUNT
PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t *, int, int, const char **);

