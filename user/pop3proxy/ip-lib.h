
/*

    File: ip-lib.h
    
    Copyright (C) 1999,2004 by Wolfgang Zekoll <wzk@quietsche-entchen.de>

    This source is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 1, or (at your option)
    any later version.

    This source is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifndef _IP_LIB_INCLUDED
#define	_IP_LIB_INCLUDED

extern char *program;
extern int debug;


typedef struct _peer {
    char	name[80];
    char	ipnum[40];
    unsigned int port;
    } peer_t;


unsigned int get_interface_info(int pfd, peer_t *sock);

int openip(char *server, unsigned int port, char *srcip, unsigned int srcport);
unsigned int get_port(char *server, unsigned int def_port);
int bind_to_port(char *interface, unsigned int port);
int acceptloop(int sock);
int getpeerinfo(int pfd, char *ipnum, int ipsize, char *name, int namesize, int interface);

#endif
