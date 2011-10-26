/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996,97 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1996,97 Jon Nelson <nels0988@tc.umn.edu>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <string.h>

#include "base64.h"

/*
 * Name: base64decode
 *
 * Description: Decodes BASE-64 encoded string
 */
int base64decode(void *dst, const char *src,int maxlen)
{
 int bitval,bits;
 int val;
 int len,x,y;

 len = strlen(src);
 bitval=0;
 bits=0;
 y=0;

 for(x=0;x<len;x++)
  {
   if ((src[x]>='A')&&(src[x]<='Z')) val=src[x]-'A'; else
   if ((src[x]>='a')&&(src[x]<='z')) val=src[x]-'a'+26; else
   if ((src[x]>='0')&&(src[x]<='9')) val=src[x]-'0'+52; else
   if (src[x]=='+') val=62; else
   if (src[x]=='-') val=63; else
    val=-1;
   if (val>=0)
    {
     bitval=bitval<<6;
     bitval+=val;
     bits+=6;
     while (bits>=8)
      {
       if (y<maxlen)
        ((char *)dst)[y++]=(bitval>>(bits-8))&0xFF;
       bits-=8;
       bitval &= (1<<bits)-1;
      }
    }
  }
 if (y<maxlen)
   ((char *)dst)[y++]=0;
 return y;
}
