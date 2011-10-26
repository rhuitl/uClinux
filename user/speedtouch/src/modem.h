/*
*  ALCATEL SpeedTouch USB modem microcode upload & ADSL link UP utility
*  Copyright (C) 2001 Benoit PAPILLAULT
*  
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*  
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*  
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
*  Author   : Benoit PAPILLAULT <benoit.papillault@free.fr>
*  Creation : 05/03/2001
*
* $Id: modem.h,v 1.4 2001/11/07 20:25:52 edgomez Exp $
*/

#ifndef _MODEM_H_
#define _MODEM_H_

/* Alcatel ADSL SpeedTouch USB modem idVendor/idProduct */
#define ST_VENDOR  0x06b9
#define ST_PRODUCT 0x4061

/* endpoint numbers */
#define EP_INT      0x81

#define EP_DATA_IN  0x87
#define EP_DATA_OUT 0x07

#define EP_CODE_IN  0x85
#define EP_CODE_OUT 0x05

/* Global Variables */
extern int verbose;

#endif
