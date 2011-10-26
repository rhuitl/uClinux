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

  cache.h -- header file containing the interface for cache modules.

  ***************************************/
#ifndef CACHE_H
#define CACHE_H

#include "config.h"
#include "sstr.h"

/*****************
**    cache.c   **
******************/
#ifdef USE_CACHE
int cache_geninit(void);
void cache_init(void);
int cache_parsed_reply(int code, sstr * msg);
void cache_inc_data(sstr * inc);
int cache_close_data(void);
int cache_transferring(void);
#else
static inline int cache_geninit(void)
{
	return (0);
};
static inline void cache_init(void)
{
};
static inline int cache_parsed_reply(int code, sstr * msg)
{
	return FALSE;
};
static inline void cache_inc_data(sstr * inc)
{
};
static inline int cache_close_data(void)
{
	return -1;
};
static inline int cache_transferring(void)
{
	return 0;
};
#endif

/* --------------------------------------------------------------- **
** This file contains the following functions for each caching module:
**
** X_geninit(char **cacheopts, char *chroot);
** Called on module load. Opts is a list of config file options
** destined for the cache. chroot is the directory we are chrooted to
** - module may need to strip this from the front of any file name
** options.
**
** X_retr_start();
** Called at the start of each file retrieval. If the cache code wants
** to return the file it should return a file descriptor. If not it
** should return -1, and the RETR command will be passed on to the
** server. 
**
** X_inc_data();
** Called with each piece of incoming data. Cache code can either
** store or modify this (or both). 
**
** X_retr_end();
** Called at the end of each file retrieval to allow cleanup.
** ------------------------------------------------------------- */

#ifdef USE_LCACHE
int l_geninit(void);
int l_retr_start(const sstr * host, const sstr * file, const sstr * mdtm,
		 int size, int offset, int type);
void l_inc_data(sstr * inc);
int l_retr_end(void);
#else
static inline int l_geninit(void)
{
	return -1;
};

# define l_retr_start NULL
# define l_inc_data NULL
# define l_retr_end NULL
#endif

#ifdef USE_HCACHE
int s_retr_start(const sstr * host, const sstr * file, const sstr * mdtm,
		 int size, int offst, int type);
void s_inc_data(sstr * inc);
int s_retr_end(void);
#else
# define s_geninit NULL
# define s_retr_start NULL
# define s_inc_data NULL
# define s_retr_end NULL
#endif

#endif /*CACHE_H */
