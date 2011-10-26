/*
 * define path names
 *
 * $Id: pathnames.h,v 1.17 2008-10-23 01:21:53 asallawa Exp $
 */

#ifdef HAVE_PATHS_H
#include <paths.h>

#else /* HAVE_PATHS_H */
#ifndef _PATH_VARRUN
#define _PATH_VARRUN 	"/etc/ppp/"
#endif
#define _PATH_DEVNULL	"/dev/null"
#endif /* HAVE_PATHS_H */

#ifndef _ROOT_PATH
#define _ROOT_PATH
#endif

#ifndef PATH_CONFIG
#define	PATH_CONFIG	"/etc/ppp"
#endif
#ifndef PATH_AUTH
#define	PATH_AUTH	"/etc/ppp"
#endif
#ifndef PATH_LOG
#define	PATH_LOG	"/etc/ppp"
#endif
#ifndef PATH_RESOLV
#define	PATH_RESOLV	"/etc/ppp"
#endif

#define _PATH_UPAPFILE 	 _ROOT_PATH PATH_CONFIG "/pap-secrets"
#define _PATH_CHAPFILE 	 _ROOT_PATH PATH_CONFIG "/chap-secrets"
#define _PATH_SRPFILE 	 _ROOT_PATH PATH_CONFIG "/srp-secrets"
#define _PATH_SYSOPTIONS _ROOT_PATH PATH_CONFIG "/options"
#define _PATH_IPUP	 _ROOT_PATH PATH_CONFIG "/ip-up"
#define _PATH_IPDOWN	 _ROOT_PATH PATH_CONFIG "/ip-down"
#define _PATH_IPPREUP	 _ROOT_PATH PATH_CONFIG "/ip-pre-up"
#define _PATH_AUTHUP	 _ROOT_PATH PATH_AUTH   "/auth-up"
#define _PATH_AUTHDOWN	 _ROOT_PATH PATH_AUTH   "/auth-down"
#define _PATH_TTYOPT	 _ROOT_PATH PATH_CONFIG "/options."
#define _PATH_CONNERRS	 _ROOT_PATH PATH_LOG    "/connect-errors"
#define _PATH_PEERFILES	 _ROOT_PATH PATH_CONFIG "/peers/"
#define _PATH_RESOLV	 _ROOT_PATH PATH_RESOLV "/%s.resolv"

#ifdef PATH_ETC_CONFIG
#define _PATH_DEFAULT_IPUP	"/etc/default/ip-up"
#define _PATH_DEFAULT_IPDOWN	"/etc/default/ip-down"
#endif

#define _PATH_USEROPT	 ".ppprc"
#define	_PATH_PSEUDONYM	 ".ppp_pseudonym"

#ifdef INET6
#define _PATH_IPV6UP     _ROOT_PATH PATH_CONFIG "/ipv6-up"
#define _PATH_IPV6DOWN   _ROOT_PATH PATH_CONFIG "/ipv6-down"
#endif

#ifdef IPX_CHANGE
#define _PATH_IPXUP	 _ROOT_PATH "/etc/ppp/ipx-up"
#define _PATH_IPXDOWN	 _ROOT_PATH "/etc/ppp/ipx-down"
#endif /* IPX_CHANGE */

#ifdef __STDC__
#define _PATH_PPPDB	_ROOT_PATH _PATH_VARRUN "pppd2.tdb"
#else /* __STDC__ */
#ifdef HAVE_PATHS_H
#define _PATH_PPPDB	"/var/run/pppd2.tdb"
#else
#define _PATH_PPPDB	"/etc/ppp/pppd2.tdb"
#endif
#endif /* __STDC__ */

#ifdef PLUGIN
#ifdef __STDC__
#define _PATH_PLUGIN	DESTDIR "/lib/pppd/" VERSION
#else /* __STDC__ */
#define _PATH_PLUGIN	"/usr/lib/pppd"
#endif /* __STDC__ */

#endif /* PLUGIN */
