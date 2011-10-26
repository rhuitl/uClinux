/* $Id: daemon.h,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
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

void	daemonInit(const char *pidfile);
/* requests: 'pidfile' pointing to the filename where daemon's pid is saved
 * effects:  it makes the process a daemon
 * modifies: nothing
 * returns:  nothing
 */

int		openMax();
/* requests: nothing
 * effects:  it returns the "maybe" maximum number of files which can be opened
 * modifies: nothing
 * returns:  nothing
 */

void	killCurProc(char *pidfile);
/* requests: 'pidfile' pointing to the file containing the process id to be
 *           terminated.
 * effects:  it terminates the running process described with 'pidfile' by
 *           sending SIGTERM signal to it.
 * modifies: nothing
 * returns:  nothing
 */
