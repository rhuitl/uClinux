/* 
 *  privs.h - header for privileged operations 
 *  Copyright (C) 1993  Thomas Koenig
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _PRIVS_H
#define _PRIVS_H

#ifndef _USE_BSD
#define _USE_BSD 1
#include <unistd.h>
#undef _USE_BSD
#else
#include <unistd.h>
#endif

/* Relinquish privileges temporarily for a setuid or setgid program
 * with the option of getting them back later.  This is done by swapping
 * the real and effective userid BSD style.  Call RELINQUISH_PRIVS once
 * at the beginning of the main program.  This will cause all operations
 * to be executed with the real userid.  When you need the privileges
 * of the setuid/setgid invocation, call PRIV_START; when you no longer
 * need it, call PRIV_END.  Note that it is an error to call PRIV_START
 * and not PRIV_END within the same function.
 *
 * Use RELINQUISH_PRIVS_ROOT(a,b) if your program started out running
 * as root, and you want to drop back the effective userid to a
 * and the effective group id to b, with the option to get them back
 * later.
 *
 * If you no longer need root privileges, but those of some other
 * userid/groupid, you can call REDUCE_PRIV(a,b) when your effective
 * is the user's.
 *
 * Problems: Do not use return between PRIV_START and PRIV_END; this
 * will cause the program to continue running in an unprivileged
 * state.
 *
 * It is NOT safe to call exec(), system() or popen() with a user-
 * supplied program (i.e. without carefully checking PATH and any
 * library load paths) with relinquished privileges; the called program
 * can aquire them just as easily.  Set both effective and real userid
 * to the real userid before calling any of them.
 */

extern uid_t real_uid, effective_uid, daemon_uid;

extern gid_t real_gid, effective_gid, daemon_gid;

#ifdef HAVE_SETREUID
#define RELINQUISH_PRIVS { \
			      real_uid = getuid(); \
			      effective_uid = geteuid(); \
			      real_gid = getgid(); \
			      effective_gid = getegid(); \
			      setreuid(effective_uid, real_uid); \
			      setregid(effective_gid, real_gid); \
		          }

#define RELINQUISH_PRIVS_ROOT(a,b) { \
			      real_uid = (a); \
			      effective_uid = geteuid(); \
			      real_gid = (b); \
			      effective_gid = getegid(); \
			      setregid(effective_gid, real_gid); \
			      setreuid(effective_uid, real_uid); \
		          }

#define PRIV_START {\
		    setreuid(real_uid, effective_uid); \
		    setregid(real_gid, effective_gid);

#define PRIV_END \
		    setregid(effective_gid, real_gid); \
		    setreuid(effective_uid, real_uid); \
		    }

#define REDUCE_PRIV(a,b) {\
			setreuid(real_uid, effective_uid); \
			setregid(real_gid, effective_gid); \
			effective_uid = (a); \
			effective_gid = (b); \
			setregid(effective_gid, real_gid); \
			setreuid(effective_uid, real_uid); \
		    }
#elif HAVE_SETRESUID
#define RELINQUISH_PRIVS { \
			      real_uid = getuid(); \
			      effective_uid = geteuid(); \
			      real_gid = getgid(); \
			      effective_gid = getegid(); \
			      setresuid(effective_uid, real_uid, -1); \
			      setresgid(effective_gid, real_gid, -1); \
		          }

/*
 * HP-UX kill(2) requires that the real or effective user ID of the
 * sender match the real or _saved_ user ID of the recipient.  In order
 * for "at" (with random real ID and effective ID "daemon") to signal
 * "atd" (with real ID "root" and effective ID "daemon"), we must make
 * "atd"'s saved ID "daemon".
 */
#define RELINQUISH_PRIVS_ROOT(a,b) { \
			      real_uid = (a); \
			      effective_uid = geteuid(); \
			      real_gid = (b); \
			      effective_gid = getegid(); \
			      setresgid(effective_gid, real_gid, real_gid); \
			      setresuid(effective_uid, real_uid, real_uid); \
		          }

#define PRIV_START {\
		    setresuid(real_uid, effective_uid, -1); \
		    setresgid(real_gid, effective_gid, -1);

#define PRIV_END \
		    setresgid(effective_gid, real_gid, -1); \
		    setresuid(effective_uid, real_uid, -1); \
		    }

#define REDUCE_PRIV(a,b) {\
			setresuid(real_uid, effective_uid, -1); \
			setresgid(real_gid, effective_gid, -1); \
			effective_uid = (a); \
			effective_gid = (b); \
			setresgid(effective_gid, real_gid, -1); \
			setresuid(effective_uid, real_uid, -1); \
		    }
#else
#error "Cannot implement user ID swapping without setreuid or setresuid"
#endif
#endif
