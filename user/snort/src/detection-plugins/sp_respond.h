/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 1999,2000,2001 Christian Lademann <cal@zls.de>
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

/*  I N C L U D E S
**********************************************************/

/*  D E F I N E S
************************************************************/
#ifndef __RESPOND_H__
#define __RESPOND_H__
#if defined(ENABLE_RESPONSE) && !defined(ENABLE_RESPONSE2)

void SetupRespond(void);

#endif /* ENABLE_RESPONSE && !ENABLE_RESPONSE2 */
#endif /* __RESPOND_H__ */
