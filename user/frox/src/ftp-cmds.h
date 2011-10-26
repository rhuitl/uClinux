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

    ftp-cmds.h					
***************************************/


#ifndef FTP_CMDS_H
#define FTP_CMDS_H		/*+ To stop multiple inclusions. + */

#include "common.h"

void ftpcmds_init(void);

struct cmd_struct {
	char name[5];
	void (*cmd) (sstr * cmd, sstr * arg);
};

extern struct cmd_struct *ftp_cmds;
void user_munge(sstr * cmd, sstr * arg);


#endif /* FTP_CMDS_H */
