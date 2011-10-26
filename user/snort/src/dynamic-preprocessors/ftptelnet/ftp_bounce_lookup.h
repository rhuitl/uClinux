/*
 * ftp_bounce_lookup.h
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
 * This file contains function definitions for bounce IP lookups.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#ifndef __FTP_BOUNCE_LOOKUP_H__
#define __FTP_BOUNCE_LOOKUP_H__

#include "ftpp_include.h"
#include "ftpp_ui_config.h"

int ftp_bounce_lookup_init(BOUNCE_LOOKUP **BounceLookup);
int ftp_bounce_lookup_cleanup(BOUNCE_LOOKUP **BounceLookup);
int ftp_bounce_lookup_add(BOUNCE_LOOKUP *BounceLookup, char ip[], int len,
                            FTP_BOUNCE_TO *BounceTo);

FTP_BOUNCE_TO *ftp_bounce_lookup_find(BOUNCE_LOOKUP *BounceLookup, 
                                            char ip[], int len, int *iError);
FTP_BOUNCE_TO *ftp_bounce_lookup_first(BOUNCE_LOOKUP *BounceLookup,
                                            int *iError);
FTP_BOUNCE_TO *ftp_bounce_lookup_next(BOUNCE_LOOKUP *BounceLookup,
                                           int *iError);

#endif
