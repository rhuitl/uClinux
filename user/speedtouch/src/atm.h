/*
*  ALCATEL SpeedTouch USB : Little atm library
*  Copyright (C) 2001 Benoit Papillault
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
*  Creation : 14/08/2001
*
* $Id: atm.h,v 1.3 2002/12/28 13:42:21 edgomez Exp $
*/

#ifndef _ATM_H_
#define _ATM_H_

/******************************************************************************
* Constants
******************************************************************************/

#define ATM_CELL_HEADER_SIZE  5
#define ATM_CELL_DATA_SIZE   48
#define ATM_CELL_TOTAL_SIZE  (ATM_CELL_HEADER_SIZE + ATM_CELL_DATA_SIZE)

/* pti bits - see uni3.1 spec?*/
#define ATM_PTI_USER_CELL   0x00
#define ATM_PTI_OAM_CELL    0x04    /* 100 */

/* User cells - we only care about the SDU bit used to signal the end of an AAL5 frame */
#define ATM_USER_SDU        (ATM_PTI_USER_CELL|0x01)  /* 001 (or 011) */

/* OAM cells - see ITU spec I.610 for details, not that we currently handle them */
#define ATM_OAM_E2E         (ATM_PTI_MNGT_CELL|0x01)
#define ATM_OAM_SEG         ATM_PTI_MNGT_CELL
#define ATM_OAM_RESERVED    (ATM_PTI_MNGT_CELL|0x02)


/******************************************************************************
* Prototypes
******************************************************************************/

	/* Cell functions */
extern void atm_header_create(unsigned char *header, int vpi, int vci, int pti, int clp);
extern int  atm_header_get_vpi(unsigned char *cell);
extern int  atm_header_get_vci(unsigned char *cell);
extern int  atm_header_get_pti(unsigned char *cell);
extern int  atm_header_get_clp(unsigned char *cell);
extern void atm_header_read(unsigned char *cell, int *vpi, int *vci, int *pti, int *clp);
extern void atm_cell_create(unsigned char *cell, unsigned char *data, int vpi, int vci, int pti, int clp);
extern void atm_cell_create_with_header(unsigned char *cell, unsigned char *data, unsigned char *header);
extern void atm_cell_read(unsigned char *data, unsigned char *cell);

	/* aal5 frame functions */
extern int aal5_frame_enc(unsigned char *frame, unsigned char *data, int length);
extern int aal5_frame_to_atm_cells(unsigned char *atm_cells, unsigned char *aal5_frame, int length, int vpi, int vci);
extern int aal5_frame_from_atm_cells(unsigned char *aal5_frame, unsigned char *atm_cells, int length, int vpi, int vci, int *cur_pos, unsigned char **atm_pointer);
extern int aal5_frame_dec(unsigned char *data, unsigned char *frame, int length);

#endif
