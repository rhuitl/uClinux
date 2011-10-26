/*
** Copyright (C) 2005 Sourcefire
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*
 * sp_urilen_check.h: Structure definitions/function prototype(s)
 * 		      for the URI length detection plugin.
 */

/* $Id */

#ifndef SP_URILEN_CHECK_H
#define SP_URILEN_CHECK_H

/* Structure stored in the rule OTN struct for use by URILEN 
 * detection plugin code.
 */
typedef struct _UriLenCheckData 
{
    int urilen;
    int urilen2;
} UriLenCheckData;

/* 
 * Structure stored in the rule OTN struct for use by URINORMLEN
 * detection plugin code.
 */
typedef struct _UriNormLenCheckData
{
    int urinormlen;
    int urinormlen2;
} UriNormLenCheckData;


extern void SetupUriLenCheck();

#endif /* SP_URILEN_CHECK_H */
