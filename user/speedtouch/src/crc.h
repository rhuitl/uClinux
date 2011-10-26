/*
*  ALCATEL SpeedTouch USB modem utility : CRC lib
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
* $Id: crc.h,v 1.5 2003/04/14 23:30:55 edgomez Exp $
*/

#ifndef _CRC_H_
#define _CRC_H_

/******************************************************************************
* Constants
******************************************************************************/

#define AAL5_CRC32_REMAINDER 0xCBF43926
#define AAL5_CRC32_INITIAL 0xffffffff

#define ATM_HEADER_REMAINDER 0x107
#define ATM_HEADER_COSET_LEADER 0x055

/******************************************************************************
* Prototype
******************************************************************************/

extern unsigned int  aal5_calc_crc(unsigned char *mem, int len, unsigned int initial);
extern unsigned char atm_calc_hec(unsigned char *header);

#endif
