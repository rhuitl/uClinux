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

    control.h functions for parsig the control stream.					
***************************************/


#ifndef CONTROL_H
#define CONTROL_H		/*+ To stop multiple inclusions. + */

#include "common.h"

void init_session(int fd, struct sockaddr_in source);
void client_control_forward(void);
void server_control_forward(void);
void parse_client_cmd(sstr * cmd, sstr * arg);
int get_control_line(int which);
void send_command(sstr * cmd, sstr * arg);
void send_message(int code, sstr * msg);
void send_ccommand(const char *cmd, const char *arg);
void send_cmessage(int code, const char *msg);
void get_command(sstr ** cmd, sstr ** arg);
void get_message(int *code, sstr ** msg);
void run_proxy(void);

#endif /* CONTROL_H */
