// $Id: arguments.h,v 1.12 2005/03/08 00:02:22 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//  

#ifndef H_IPSENTINEL_ARGUMENTS_H
#define H_IPSENTINEL_ARGUMENTS_H

#include <stdbool.h>
#include <net/ethernet.h>

struct TaggedMac
{
    enum {mcRANDOM, mcFIXED,
	  mcLOCAL, mcSAME}	type;

    union {
	struct ether_addr	ether;
    }				addr;
};

struct Arguments
{
    char const *	ipfile;
    char const *	pidfile;
    char const *	logfile;
    char const *	errfile;
    char const *	user;
    char const *	group;
    bool		do_fork;
    char const *	chroot;
    char const *	iface;
    bool		do_poison;
    char const *	action_cmd;

    enum {dirFROM=1, dirTO=2,
	  dirBOTH=3}	arp_dir;
    struct TaggedMac	mac;
    struct TaggedMac	llmac;
};

void	parseOptions(int argc, char *argv[], struct Arguments *options);
void	Arguments_fixupOptions(struct Arguments *options);

#endif	//  H_IPSENTINEL_ARGUMENTS_H
