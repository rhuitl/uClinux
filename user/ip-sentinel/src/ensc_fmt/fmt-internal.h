// $Id: fmt-internal.h,v 1.2 2004/08/19 13:53:54 ensc Exp $    --*- c -*--

// Copyright (C) 2003 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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


#ifndef H_UTIL_VSERVER_LIB_FMT_COMMON_H
#define H_UTIL_VSERVER_LIB_FMT_COMMON_H

#define DIGITS			"0123456789abcdefghijklmnopqrstuvwxyz"

#define FMT_P__(X,Y)		X ## Y
#define FMT_P_(X,Y)		FMT_P__(X,Y)
#define FMT_P(X)		FMT_P_(FMT_PREFIX, X)

#define CONCAT__(x,y,z)		x ## y ## z
#define CONCAT_(x,y,z)		CONCAT__(x,y,z)
#define CONCAT(x,z)		CONCAT_(x, FMT_BITSIZE, z)

#define FMT_FN(BASE,SZ)					\
  do {							\
    register __typeof__(val)	v = val;		\
    register size_t		l = 0;			\
  							\
    if (ptr==0) {					\
      do {						\
        ++l;						\
        v /= BASE;					\
      } while (v!=0);					\
    }							\
    else {						\
      char			buf[sizeof(val)*SZ];	\
  							\
      do {						\
	register unsigned int	d = v%BASE;		\
	v /= BASE;					\
        ++l;						\
        buf[sizeof(buf)-l] = DIGITS[d];			\
      } while (v!=0);					\
  							\
      memcpy(ptr, buf+sizeof(buf)-l, l);		\
    }							\
  							\
    return l;						\
  } while (0)


#endif	//  H_UTIL_VSERVER_LIB_FMT_COMMON_H
