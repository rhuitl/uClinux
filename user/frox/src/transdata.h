/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  transdata.h
  
  ***************************************/

#ifndef TRANSDATA_H
#define TRANSDATA_H		/*+ To stop multiple inclusions. + */

#include <sys/types.h>
#include "common.h"
#include "os.h"

#ifdef TRANS_DATA

void transdata_setup(void);
void transdata_newsocketpair(void);
int transdata_needprivs(void);
int transp_connect(struct sockaddr_in dest, struct sockaddr_in src);
int intercept_listen(struct sockaddr_in intercept,
		     struct sockaddr_in listen_on, int portrange[2]);
int il_free(void);
void transdata_flush(void);
#else
static inline void transdata_setup(void)
{
};
static inline void transdata_newsocketpair(void)
{
};
static inline int transdata_needprivs(void)
{
	return FALSE;
};
static inline int transp_connect(struct sockaddr_in dest,
				 struct sockaddr_in src)
{
	return -1;
};
static inline int intercept_listen(struct sockaddr_in intercept,
				   struct sockaddr_in listen_on,
				   int portrange[2])
{
	return -1;
};
static inline int il_free(void)
{
	return -1;
};
static inline void transdata_flush(void)
{
};
#endif

#endif /* TRANSDATA_H */
