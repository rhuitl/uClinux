/*
*  ALCATEL SpeedTouch USB modem utility : PPPoA implementation (3nd edition)
*  Copyright (C) 2001 Edouard Gomez
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
*  Author : Edouard Gomez (ed.gomez@free.fr)
*  Creation : 08/08/2001
*
* $Id: pppoa3.h,v 1.5 2003/08/06 01:37:46 rogler Exp $
*/

#ifndef _PPPOA3_H_
#define _PPPOA3_H_

/******************************************************************************
* Constants
******************************************************************************/

/* Alcatel ADSL SpeedTouch USB modem idVendor/idProduct */
#define ST_VENDOR  0x06b9
#define ST_PRODUCT 0x4061

/* Endpoint numbers */
#define EP_INT      0x81

#define EP_DATA_IN  0x87
#define EP_DATA_OUT 0x07

#define EP_CODE_IN  0x85
#define EP_CODE_OUT 0x05

/* report flags*/
	/* actions */
#define REPORT_DATE         ((unsigned int)0x00000001)
#define REPORT_PERROR       ((unsigned int)0x00000002)
#define REPORT_DUMP         ((unsigned int)0x00000004)
	/* message types */
#define REPORT_ERROR        ((unsigned int)0x00000010)
#define REPORT_INFO         ((unsigned int)0x00000020)
#define REPORT_DEBUG        ((unsigned int)0x00000040)


/******************************************************************************
* Prototypes (also used in atm.c)
******************************************************************************/

extern void report( int minlevel, unsigned int flags, const char *format, ...);

#endif

