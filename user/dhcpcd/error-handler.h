/* $Id: error-handler.h,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 Yoichi Hariguchi <yoichi@fore.com>
 *
 * Dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

extern int errno;


/* logXXX outputs error message to stderr if DebugFlag is 1
 * logXXX sends error message to syslog  if DebugFlag is 0
 */
extern int DebugFlag;


/* function prototypes
 */

void	errSysExit(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  outputs system and user specified error messages to stderr,
 *           and terminates the process with exit(1).
 * modifies: nothing
 * returns:  nothing
 * comment:  call this when a system call related error occured and want to
 *           terminate the process.
 */

void	errSysRet(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  outputs system and user specified error messages to stderr.
 * modifies: nothing
 * returns:  nothing
 * comment:  call this when a system call related error occured.
 */

void	errQuit(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  outputs user specified error messages to stderr, and terminates
 *           the process with exit(1).
 * modifies: nothing
 * returns:  nothing
 */

void	errMsg(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  outputs user specified error messages to stderr.
 * modifies: nothing
 * returns:  nothing
 */

void	logOpen(const char *ident, int option, int facility);
/* requests: ident:  ptr to program name
 *           option:   one of LOG_{CONS, NDELAY, PERROR, PID}
 *           facility: LOG_XXX in syslog.h (XXX is LOCAL0, USER, etc.)
 * effects:  it calles 'openlog' if 'DebugFlag' is 1, othewise does nothing.
 * modifies: nothing
 * returns:  nothing
 */

void	logSysExit(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  it sends system and user specified error messages to syslog
 *           if 'DebugFlag' is 1, otherwise outputs them to stderr. it also
 *           terminates the process with 'exit(2)'.
 * modifies: nothing
 * returns:  nothing
 * comment:  call this when a system call related error occured.
 */

void	logSysRet(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  it sends system and user specified error messages to syslog
 *           if 'DebugFlag' is 1, otherwise outputs them to stderr.
 * modifies: nothing
 * returns:  nothing
 * comment:  call this when a system call related error occured.
 */

void	logQuit(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  it sends user specified error messages to syslog 
 *           if 'DebugFlag' is 1, otherwise outputs them to stderr. it also
 *           terminates the process with 'exit(2)'.
 * modifies: nothing
 * returns:  nothing
 */

void	logRet(const char *fmt, ...);
/* requests: parameters same as 'printf'
 * effects:  it sends user specified error messages to syslog 
 *           if 'DebugFlag' is 1, otherwise outputs them to stderr.
 * modifies: nothing
 * returns:  nothing
 */
