/*
    Copyright (C) 2002-2005  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.
    
    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    
    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/

/* $Id: log.h,v 1.11 2005/01/08 10:05:12 hb9xar Exp $ */

#include <stdarg.h>

#define DBCLASS_BABBLE	0x00000001	/* babble (like entering/leaving fnc)*/
#define DBCLASS_NET	0x00000002	/* network			     */
#define DBCLASS_SIP	0x00000004	/* SIP manipulations		     */
#define DBCLASS_REG	0x00000008	/* Client registration		     */
#define DBCLASS_NOSPEC	0x00000010	/* non specified class		     */
#define DBCLASS_PROXY	0x00000020	/* proxy			     */
#define DBCLASS_DNS	0x00000040	/* DNS stuff			     */
#define DBCLASS_NETTRAF	0x00000080	/* network traffic		     */
#define DBCLASS_CONFIG	0x00000100	/* configuration		     */
#define DBCLASS_RTP	0x00000200	/* RTP proxy			     */
#define DBCLASS_ACCESS	0x00000400	/* Access list evaluation	     */
#define DBCLASS_AUTH	0x00000800	/* Authentication		     */
#define DBCLASS_ALL	0xffffffff	/* All	classes			     */


void log_set_pattern(int pattern);
int  log_get_pattern(void);
void log_set_stderr(int tostdout);
void log_set_silence(int level);
void log_set_listen_port(int port);
void log_tcp_listen(void);
void log_tcp_connect(void);

#undef DEBUG
#define DEBUG(F...) log_debug(1,__FILE__, __LINE__,F)

#define DEBUGC(C,F...) log_debug(C,__FILE__, __LINE__,F)
void log_debug(int class, char *file, int line, const char *format, ...);

#define ERROR(F...) log_error(__FILE__, __LINE__,F)
void log_error(char *file, int line, const char *format, ...);

#define WARN(F...) log_warn(__FILE__, __LINE__,F)
void log_warn(char *file, int line, const char *format, ...);

#define INFO(F...) log_info(__FILE__, __LINE__,F)
void log_info(char *file, int line, const char *format, ...);

/* tobedone: dump a buffer */
#define DUMP_BUFFER(C,F,L) log_dump_buffer(C,__FILE__, __LINE__,F,L)
void log_dump_buffer(int class, char *file, int line,
                     char *buffer, int length);
