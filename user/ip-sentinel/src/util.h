// $Id: util.h,v 1.14 2005/03/29 15:49:58 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004,2005 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef H_IPSENTINEL_UTIL_H
#define H_IPSENTINEL_UTIL_H

#include <stdlib.h>
#include <sys/param.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>


  /*@-namechecks@*/
#ifndef __cplusplus
#  define cAsT_(X)              (X))
#  define reinterpret_cast(X)   ((X) cAsT_
#  define static_cast(X)        ((X) cAsT_
#  define const_cast(X)         ((X) cAsT_
#else   /* __cplusplus */
#  define reinterpret_cast(X)   reinterpret_cast<X>
#  define static_cast(X)        static_cast<X>
#  define const_cast(X)         const_cast<X>
#endif
  /*@=namechecks@*/

#ifndef S_SPLINT_S
#  define assertDefined(x)
#endif

#define WRITE_MSG(fd,str)	Vwrite(fd, str, strlen(str))
#define WRITE_MSGSTR(fd,str)	Vwrite(fd, str, sizeof(str)-1)

#define XSTRCAT(dst, cnt, src)	xstrcatn(dst, cnt, src, sizeof(src)-1)

#define SETCLOEXEC(FD)		Efcntl_l(FD, F_SETFD, FD_CLOEXEC)

struct ether_addr *
xether_aton_r(char const *asc, struct ether_addr *addr);


inline static void
Vwrite(int fd, char const *buf, size_t len)
{
  if (write(fd,buf,len)==-1) { /**/ }
}

inline static void
xstrcatn(char **dst, size_t *cnt, char const *src, size_t src_len)
{
  size_t	len     = MIN(*cnt, src_len);
  memcpy(*dst, src, len);

  *cnt -= len;
  *dst += len;
}


inline static void
xstrcat(char **dst, size_t *cnt, char const *src)
{
  xstrcatn(dst, cnt, src, strlen(src));
}

void writeUInt(int fd, unsigned int nr);
void writeMsgTimestamp(int fd);
void writeIP(int fd, struct in_addr);

void	Util_setRandomMac(struct ether_addr *res);

#endif	//  H_IPSENTINEL_UTIL_H
