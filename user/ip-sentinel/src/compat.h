// $Id: compat.h,v 1.13 2005/03/08 10:58:48 ensc Exp $    --*- c++ -*--

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

#ifndef H_ENSC_IPSENTINEL_SRC_COMPAT_H
#define H_ENSC_IPSENTINEL_SRC_COMPAT_H

#if defined(__dietlibc__) && !defined(ENSC_DIETLIBC_C99) && defined(__STRICT_ANSI__) && defined(__STDC_VERSION__)
  // fixed in 0.25+
#  include <sys/cdefs.h>
#  undef inline

#  undef  __STRICT_ANSI__
#  include <stdint.h>
#  define __STRICT_ANSI__
#endif

#ifdef __dietlibc__
  // fixed in 0.27+
#  define ethhdr		ethhdrX
#  include <net/ethernet.h>
#  undef  ethhdr

#  ifndef HAVE_DIET_ETHER_NTOA
char *			ether_ntoa(struct ether_addr const *addr);
#  endif

#  ifndef HAVE_DIET_ETHER_NTOA_R
struct ether_addr *	ether_aton_r(const char *asc, struct ether_addr *addr);
#  endif
#endif


#ifndef __dietlibc__
#ifdef __GLIBC__
#  include <stropts.h>
#endif
#else
#  include <sys/ioctl.h>
#endif

#ifdef __dietlibc__
#  define sin	XsinX
#endif
#include <netinet/in.h>
#undef sin


#ifdef __dietlibc__
#include <net/if_arp.h>
#include <stdint.h>

struct  ether_arp {
        struct  arphdr ea_hdr;          /* fixed-size header */
        uint8_t arp_sha[ETH_ALEN];     /* sender hardware address */
        uint8_t arp_spa[4];            /* sender protocol address */
        uint8_t arp_tha[ETH_ALEN];     /* target hardware address */
        uint8_t arp_tpa[4];            /* target protocol address */
};
#endif

#if  (defined(__dietlibc__) && !defined(DIET_HAS_IN_ADDR_T)) ||  \
    (!defined(__dietlibc__) && !defined(HAVE_IN_ADDR_T))
  typedef uint32_t      in_addr_t;
#endif

#ifndef __GLIBC__
# define TEMP_FAILURE_RETRY(expression)			\
  (__extension__					\
    ({ long int __result;				\
       do __result = (long int) (expression);		\
       while (__result == -1L && errno == EINTR);	\
       __result; }))
#endif

#if !defined(HAVE_DECL_STRDUPA) || !HAVE_DECL_STRDUPA
  // from glibc's <string.h>
#  if defined __GNUC__
/* Duplicate S, returning an identical alloca'd string.  */
#   define strdupa(s)                                                           \
  (__extension__                                                              \
    ({                                                                        \
      __const char *__old = (s);                                              \
      size_t __len = strlen (__old) + 1;                                      \
      char *__new = (char *) __builtin_alloca (__len);                        \
      (char *) memcpy (__new, __old, __len);                                  \
    }))
#  endif
#endif

#if defined(__GNUC__)
#  define UNUSED		__attribute__((__unused__))
#  define NORETURN		__attribute__((__noreturn__))
#  if __GNUC__ >= 3
#    define ALWAYSINLINE	__attribute__((__always_inline__))
#  else
#    define ALWAYSINLINE
#  endif
#else
#  define UNUSED
#  define NORETURN
#  define ALWAYSINLINE
#endif

#endif	//  H_ENSC_IPSENTINEL_SRC_COMPAT_H
