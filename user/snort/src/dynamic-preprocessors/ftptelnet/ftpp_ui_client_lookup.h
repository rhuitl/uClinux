/*
 * ftpp_ui_client_lookup.h
 *
 * Copyright (C) 2004 Sourcefire,Inc
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
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
 * This file contains function definitions for client lookups.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#ifndef __FTPP_UI_CLIENT_LOOKUP_H__
#define __FTPP_UI_CLIENT_LOOKUP_H__

#include "ftpp_include.h"
#include "ftpp_ui_config.h"

int ftpp_ui_client_lookup_init(CLIENT_LOOKUP **ClientLookup);
int ftpp_ui_client_lookup_cleanup(CLIENT_LOOKUP **ClientLookup);
int ftpp_ui_client_lookup_add(CLIENT_LOOKUP *ClientLookup, unsigned long IP,
                            FTP_CLIENT_PROTO_CONF *ClientConf);

FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_find(CLIENT_LOOKUP *ClientLookup, 
                                            unsigned long Ip, int *iError);
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_first(CLIENT_LOOKUP *ClientLookup,
                                            int *iError);
FTP_CLIENT_PROTO_CONF *ftpp_ui_client_lookup_next(CLIENT_LOOKUP *ClientLookup,
                                           int *iError);

#endif
