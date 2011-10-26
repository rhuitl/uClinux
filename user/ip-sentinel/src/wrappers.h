// $Id: wrappers.h,v 1.11 2005/03/29 02:09:29 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//  

#ifndef H_IPSENTINEL_WRAPPERS_H
#define H_IPSENTINEL_WRAPPERS_H

#include <unistd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>

  /*@-internalglobs@*//*@-modfilesys@*/
  /*@unused@*//*@noreturnwhentrue@*/
inline static void
FatalErrnoError(bool condition, int retval, char const msg[]) /*@*/
{
  if (!condition)       return;

#if 0  
  char          *str = strerror(errno);
  write(2, msg, strlen(msg));
  write(2, ": ", 2);
  write(2, str, strlen(str));
  write(2, "\n", 1);
#else
  perror(msg);
#endif

  exit(retval);
}
  /*@=internalglobs@*//*@=modfilesys@*/


inline static int
Eopen(char const *fname, int flags, mode_t mode)
{
  int	res = open(fname, flags, mode);
  FatalErrnoError(res==-1, 1, "open()");

  return res;
}

/*@unused@*/
inline static /*@observer@*/ struct group const *
Egetgrnam(char const *name)
    /*@*/
{
  struct group const   *res = getgrnam(name);
  FatalErrnoError(res==0, 1, "getgrnam()");

  return res;
}

/*@unused@*/
inline static /*@observer@*/ struct passwd const *
Egetpwnam(char const *name)
    /*@*/
{
  struct passwd const   *res = getpwnam(name);
  FatalErrnoError(res==0, 1, "getpwnam()");

  return res;
}

/*@unused@*/
inline static /*@observer@*/ struct passwd const *
Egetpwuid(uid_t uid)
    /*@*/
{
  struct passwd const   *res = getpwuid(uid);
  FatalErrnoError(res==0, 1, "getpwuid()");

  return res;
}

inline static void
Eioctl(int fd, int request, void *param)
{
  int	res = ioctl(fd, request, param);
  FatalErrnoError(res==-1, 1, "ioctl()");
}

/*@unused@*/
inline static void
Echroot(char const path[])
  /*@globals internalState, errno@*/
  /*@modifies internalState, errno@*/
  /*@warn superuser "Only super-user processes may call Echroot."@*/
{
    /*@-superuser@*/
  FatalErrnoError(chroot(path)==-1, 1, "chroot()");
    /*@=superuser@*/  
}

/*@unused@*/
inline static void
Echdir(char const path[])
  /*@globals internalState, errno@*/
  /*@modifies internalState, errno@*/
{
  FatalErrnoError(chdir(path)==-1, 1, "chdir()");
}

/*@unused@*/
inline static void
Esetuid(uid_t uid)
  /*@globals internalState, fileSystem, errno@*/
  /*@modifies internalState, fileSystem, errno@*/
{
  FatalErrnoError(setuid(uid)==-1, 1, "setuid()");
}

/*@unused@*/
inline static void
Esetgid(gid_t gid)
  /*@globals internalState, fileSystem, errno@*/
  /*@modifies internalState, fileSystem, errno@*/
{
  FatalErrnoError(setgid(gid)==-1, 1, "setgid()");
}

/*@unused@*/
inline static void
Esetgroups(size_t size, const gid_t *list)
    /*@globals internalState@*/
    /*@modifies internalState@*/
{
  FatalErrnoError(setgroups(size, list)==-1, 1, "setgroups()");
}

/*@unused@*/
inline static void
Eclose(int s)
    /*@globals internalState, fileSystem, errno@*/
    /*@modifies internalState, fileSystem, errno@*/
{
  FatalErrnoError(close(s)==-1, 1, "close()");
}

/*@unused@*/
inline static int
Edup2(int oldfd, int newfd)
    /*@globals internalState, fileSystem@*/
    /*@modifies internalState, fileSystem@*/
{
  int           res = dup2(oldfd, newfd);

  FatalErrnoError(res==-1, 1, "dup2()");

  return res;
}

/*@unused@*/
inline static pid_t
Esetsid()
{
  pid_t         res = setsid();
  FatalErrnoError(res==-1, 1, "setsid()");

  return res;
}

/*@unused@*/
inline static size_t
Ewrite(int fd, void const *ptr, size_t len)
{
  size_t	res = write(fd, ptr, len);
  FatalErrnoError((ssize_t)(res)==-1, 1, "write()");

  return res;
}

/*@unused@*/
inline static int 
Esocket(int domain, int type, int protocol)
    /*@globals internalState@*/
    /*@modifies internalState@*/
{
  register int          res = socket(domain, type, protocol);
  FatalErrnoError(res==-1, 1, "socket()");

  return res;
}

/*@unused@*/
inline static pid_t
Efork()
{
  pid_t		res = fork();
  FatalErrnoError(res==-1, 1, "fork()");

  return res;
}

/*@unused@*/
inline static int
Ebind(int sock, void const *addr, int addrlen)
{
  int		res = bind(sock, addr, addrlen);
  FatalErrnoError(res==-1, 1, "bind()");

  return res;
}

/*@unused@*/
inline static /*@null@*//*@only@*/ void *
Erealloc(/*@only@*//*@out@*//*@null@*/ void *ptr,
         size_t new_size)
    /*@ensures maxSet(result) == new_size@*/
    /*@modifies *ptr@*/
{
  register void         *res = realloc(ptr, new_size);
  FatalErrnoError(res==0 && new_size!=0, 1, "realloc()");

  return res;
}

/*@unused@*/
inline static /*@null@*//*@only@*/ void *
Emalloc(size_t size)
    /*@*/
    /*@ensures maxSet(result) == size@*/
{
  register void /*@out@*/               *res = malloc(size);
  FatalErrnoError(res==0 && size!=0, 1, "malloc()");
    /*@-compdef@*/
  return res;
    /*@=compdef@*/
}

inline static void
Epipe(int modus[2])
{
  register int		res = pipe(modus);
  FatalErrnoError(res==-1, 1, "pipe()");
}

inline static int
Efcntl_l(int fd, int cmd, long arg)
{
  register int		res = fcntl(fd, cmd, arg);
  FatalErrnoError(res==-1, 1, "fcntl()");
  return res;
}

inline static sighandler_t
Esignal(int signum, sighandler_t handler)
{
  sighandler_t		res = signal(signum, handler);
  FatalErrnoError(res==SIG_ERR, 1, "signal()");
  return res;
}

#endif	//  H_IPSENTINEL_WRAPPERS_H
