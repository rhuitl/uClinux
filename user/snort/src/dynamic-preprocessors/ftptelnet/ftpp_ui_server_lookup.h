/*
 * ftpp_ui_server_lookup.h
 *
 * Copyright (C) 2004 Sourcefire,Inc
 * Steven A. Sturges <ssturges@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 *
 * This file contains function definitions for server lookups.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#ifndef __FTPP_UI_SERVER_LOOKUP_H__
#define __FTPP_UI_SERVER_LOOKUP_H__

#include "ftpp_include.h"
#include "ftpp_ui_config.h"

int ftpp_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup);
int ftpp_ui_server_lookup_cleanup(SERVER_LOOKUP **ServerLookup);
int ftpp_ui_server_lookup_add(SERVER_LOOKUP *ServerLookup, unsigned long IP,
                            FTP_SERVER_PROTO_CONF *ServerConf);

FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_find(SERVER_LOOKUP *ServerLookup, 
                                            unsigned long Ip, int *iError);
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_first(SERVER_LOOKUP *ServerLookup,
                                            int *iError);
FTP_SERVER_PROTO_CONF *ftpp_ui_server_lookup_next(SERVER_LOOKUP *ServerLookup,
                                           int *iError);

#endif
