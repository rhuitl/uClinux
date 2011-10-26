/* $Id: hostinfo.h,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
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

void	setupOptInfo(u_char *dest[], const u_char *src[]);
/*  requires: 'dest[]' to which contents described by 'src[]' are copied 
 *            'src[]' pointing to each option field of DHCP message
 *  effects:  it allocates memory for each content of 'src[i]', puts it into
 *            'dest[i]', and copies each content of 'src[i]' to 'dest[i]'.
 *            old 'dest[i]' is overwritten by 'src[i]'
 *  modifies: 'dest[]'
 *  return:   Nothing
 */

void	freeOptInfo(u_char *optp[]);
/*  requires: 'optp[]' pointing to each option field of DHCP message
 *  effects:  it frees all the memory which is allocated to 'optp[]'
 *            NULL is assigned to the freed elements
 *  modifies: 'optp[]'
 *  return:   Nothing
 */

void	saveHostInfo(const u_char *optp[]);
/*  requires: 'optp[]' pointing to each option field of DHCP message
 *  effects:  it sets the system's hostname, NIS dommain name if the DHCP
 *            message includes these items. it also makes files 'resolv.conf'
 *            and 'hostinfo' in the directory HOST_INFO_DIR
 *  modifies: Nothing
 *  return:   Nothing
 */

int		setupHostInfoDir(const char *dir);
/*  requires: 'dir' pointing to the directory name
 *  effects:  it makes the directory '*dir'. it also removes it if there is
 *            a normal file called '*dir'.
 *  modifies: Nothing
 *  return:   1 if successful, 0 if failed
 */

void	addHostInfo(int fd, const int flag,
					const char *name, const u_char *optp);
/*  requires: 'fd' containing file descripter of the hostinfo file
 *            'flag' must be OT_STRING if 'optp' points a string
 *            'flag' must be OT_ADDR if 'optp' points an address
 *            'name' points the environment valiable name corresponding to
 *            '*optp'
 *            '*outp' must point to the proper DHCP message option field
 *  effects:  it appends '*name' and '*optp' to the file described with 'fd'
 *  modifies: Nothing
 *  return:   Nothing
 */

void	mkNTPconf(const u_char *addr);
/*  requires: 'addr' pointing NTP servers option field of the DHCP message
 *  effects:  it makes the file ntp.conf in the directory HOST_INFO_DIR.
 *            it also saves NTP server address(es) into the file
 *            HOST_INFO_DIR/ntp.conf
 *  modifies: Nothing
 *  return:   Nothing
 */

void	mkResolvConf(const u_char *addr, const u_char *domName);
/*  requires: 'addr' pointing DNS servers option field of the DHCP message
 *            'domName' pointing domain name option field of the DHCP message
 *  effects:  it makes the file resolv.conf in the directory HOST_INFO_DIR.
 *            it also saves domain name and DNS server address(es) into
 *            the file HOST_INFO_DIR/resolv.conf.
 *  modifies: Nothing
 *  return:   Nothing
 */

void	execCommandFile();
