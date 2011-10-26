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
* $Id: atm.c,v 1.11 2003/06/30 21:11:25 edgomez Exp $
*/

#ifndef _ATM_C_
#define _ATM_C_

#include <stdio.h>
#include <string.h>

/* Prototypes */
#include "atm.h"

/* report function */
#include "pppoa3.h"

/* Crc function */
#include "crc.h"

/******************************************************************************
* ATM cell related Functions
******************************************************************************/

/*
* Function     : atm_header_create
* Return value : none
* Description  : Creates an atm cell header to (vpi, vci, pti, clp)
*/

void atm_header_create(unsigned char *header, int vpi, int vci, int pti, int clp)
{

	/*
	* ATM UNI cell header
	*
	*  8     7     6     5     4     3     2     1  
	* *************************************************
	* *          GFC        *          VPI            *
	* *************************************************
	* *         (VPI)       *                         *
	* ***********************                         *
	* *                      VCI                      *
	* *                     ***************************
	* *                     *         PTI     *  CLP  *
	* *************************************************
	* *                Header CRC                     *
	* *************************************************
	*
	*/

	vpi &= 0x000000ff;
	vci &= 0x0000ffff;
	pti &= 0x00000007;
	clp &= 0x00000001;

	header[0] =  (vpi >> 4);
	header[1] =  (vpi << 4) | (vci >> 12);
	header[2] =  (vci & 0x00000ff0) >> 4;
	header[3] = ((vci & 0x0000000f) << 4) | (pti << 1) | clp;
#ifdef DEBUG
	header[4] =  atm_calc_hec(header);
#else
	header[4] = 0xec; /* Arbitrary constant */
#endif
	
}

/*
* Function     : atm_header_get_vpi
* Return value : Returns the vpi value of the given ATM UNI cell header
* Description  : Look at the return value
*/

int atm_header_get_vpi(unsigned char *cell)
{

	return((((int)cell[0])<<4) | (((int)cell[1])>>4));

}

/*
* Function     : atm_header_get_vci
* Return value : Returns the vci value of the given ATM UNI cell header
* Description  : Look at the return value
*/

int atm_header_get_vci(unsigned char *cell)
{

	return((((int)(cell[1]&0x0f))<<12) | (((int)cell[2])<<4) | (((int)(cell[3]&0xf0))>>4));

}

/*
* Function     : atm_header_get_pti
* Return value : Returns the pti value of the given ATM UNI cell header
* Description  : Look at the return value
*/

int atm_header_get_pti(unsigned char *cell)
{

	return((cell[3]&0x0e)>>1);

}

/*
* Function     : atm_header_get_clp
* Return value : Returns the clp value of the given ATM UNI cell header
* Description  : Look at the return value
*/

int atm_header_get_clp(unsigned char *cell)
{

	return(cell[3]&0x01);

}

/*
* Function     : atm_header_get_vpi
* Return value : Returns all the header infos
* Description  : Look at the return value
*/

void atm_header_read(unsigned char *cell, int *vpi, int *vci, int *pti, int *clp)
{

	*vpi = atm_header_get_vpi(cell);
	*vci = atm_header_get_vci(cell);
	*pti = atm_header_get_pti(cell);
	*clp = atm_header_get_clp(cell);

}

/*
* Function     : atm_cell_create
* Return value : none
* Description  : Creates an atm cell according to (vpi, vci, pti, clp) and data
*/

void atm_cell_create(unsigned char *cell, unsigned char *data, int vpi, int vci, int pti, int clp)
{

	memmove(cell + ATM_CELL_HEADER_SIZE, data, ATM_CELL_DATA_SIZE);
	atm_header_create(cell, vpi, vci, pti, clp);

}

/*
* Function     : atm_cell_create_with_header
* Return value : none
* Description  : Creates an atm cell according to the header template given and data
*/

void atm_cell_create_with_header(unsigned char *cell, unsigned char *data, unsigned char *header)
{

	memmove(cell + ATM_CELL_HEADER_SIZE, data, ATM_CELL_DATA_SIZE);
	memmove(cell, header, ATM_CELL_HEADER_SIZE);

}

/*
* Function     : atm_cell_read
* Return value : none
* Description  : extract data from the atm cell
*/

void atm_cell_read(unsigned char *data, unsigned char *cell)
{

	memmove(data, cell + ATM_CELL_HEADER_SIZE, ATM_CELL_DATA_SIZE);

}

/******************************************************************************
* AAL5 frame related Functions
******************************************************************************/

/*
* Function     : aal5_frame_enc
* Return value : aal5 frame's size
* Description  : Encapsulate data in an aal5 frame ( data + pad + aal5 header)
*/

int aal5_frame_enc(unsigned char *frame, unsigned char *data, int length)
{

	unsigned int crc;
	unsigned int total_length;

	if(frame != data)
		memcpy(frame, data, length);

	total_length = ATM_CELL_DATA_SIZE * ((length + 8 + ATM_CELL_DATA_SIZE - 1) / ATM_CELL_DATA_SIZE);

	memset(frame + length, 0, total_length - length);

	frame[total_length - 6] = (length & 0x0000ff00)>>8;
	frame[total_length - 5] = (length & 0x000000ff);

	crc = ~aal5_calc_crc(frame, total_length - 4, ~0);

	frame[total_length - 4] = (crc & 0xff000000)>>24;
	frame[total_length - 3] = (crc & 0x00ff0000)>>16;
	frame[total_length - 2] = (crc & 0x0000ff00)>> 8;
	frame[total_length - 1] = (crc & 0x000000ff);

	return(total_length);

}

/*
* Function     : aal5_frame_to_atm_cells
* Return value : -1 if the aal5 frame is not recognized (its length is not %48)
*                or atm cell buffer size
* Description  : given an aal5 frame, build an atm cell queue
*/

int aal5_frame_to_atm_cells(unsigned char *atm_cells, unsigned char *aal5_frame, int length, int vpi, int vci)
{

	unsigned char *src, *dst;
	unsigned char header[5];
	unsigned int cells;

	if(length%ATM_CELL_DATA_SIZE)
		return(-1);

	cells = length/ATM_CELL_DATA_SIZE - 1;

	/*
	* We will write atm cells from last to first
	* This allow us to use the same buffer for src and dst
	* This cell must have pti = 1 to mark end af the aal5 frame
	*/

	src = aal5_frame + ATM_CELL_DATA_SIZE *cells;
	dst = atm_cells  + ATM_CELL_TOTAL_SIZE*cells;
	atm_header_create(header, vpi, vci, 1, 0);

	atm_cell_create_with_header(dst, src, header);

	/* (Re)Create the header */
	atm_header_create(header, vpi, vci, 0, 0);

	/* Build all the other cells */
	while(cells--) {

		src -= ATM_CELL_DATA_SIZE;
		dst -= ATM_CELL_TOTAL_SIZE;
		atm_cell_create_with_header(dst, src, header);

	}

	return((length/ATM_CELL_DATA_SIZE) * ATM_CELL_TOTAL_SIZE);
		
}

/*
* Function     : aal5_frame_from_atm_cells
* Return value : -1 buffer overflow
*                 0 if all good
*                 1 if all good and the last aal5_frame cell has been detected
*                  ( look at the atm_pointer to see if we have unused cells )
*                  ( atm_pointer == NULL if there is no unused cells        )
*                  ( else atm_pointer points to the first unused cell       )
*                  ( so you can call aal5_frame_from_atm_cell again to start)
*                  ( another aal5 frame with the unused cells               )
* Description  : ...
*/

int aal5_frame_from_atm_cells(unsigned char *aal5_frame, unsigned char *atm_cells, int length, int vpi, int vci, int *cur_pos, unsigned char **atm_pointer)
{

	int pti;
	unsigned int tmp;
	unsigned char *src,*dst;

	/* Init source and destination */
	src = atm_cells;
	dst = aal5_frame + *cur_pos;

	/* There's sometimes junk bytes in atm_cells_buffer */
	tmp = length % ATM_CELL_TOTAL_SIZE;

	/* We skip junk bytes until the next ATM cell */
	if(tmp) {

		int i;
		
		/*
		 * We should find a cell's beginning before an ATM cell size
		 * byte range from current position
		 */
		for(i=0; i<ATM_CELL_TOTAL_SIZE - 4; i++) {

			/* First we try finding VPI/VCI */
			if(atm_header_get_vpi(src + i) == vpi &&
			   atm_header_get_vci(src + i) == vci &&
			   atm_calc_hec(src + i)       == *(src + i + 4)) {
				src += i;
				length -= i;
				break;
			}
		}
		if (i > 0) report(0, REPORT_ERROR|REPORT_DATE, "Junk bytes....\n");
	}


	pti = 0;

	while(length>0) {

		if(*cur_pos + ATM_CELL_DATA_SIZE > (64*1024 - 1)) {
			*cur_pos = 0;
			return(-1);
		}

		/* Skip cells that don't use the same vpi, vci as ours */
		if( vpi != atm_header_get_vpi(src) || vci != atm_header_get_vci(src)) {
			report(0, REPORT_INFO|REPORT_DATE, "Cell had wrong VPI(%d)/VCI(%d) (OAM?) PTI=0x%.2x\n",
				atm_header_get_vpi(src),
				atm_header_get_vci(src),
				atm_header_get_pti(src));
			src      += ATM_CELL_TOTAL_SIZE;
			length   -= ATM_CELL_TOTAL_SIZE;
			/* Reset pti because this _could_ be the last cell in the buffer */
			pti = 0;
			continue;
		}

		pti = atm_header_get_clp(src);
		if (pti > 0) {
			report(0, REPORT_ERROR|REPORT_DATE, "Clp bit is ON\n");
		}
		pti = atm_header_get_pti(src);

		/* 
		* If the Managment PTI bit is set we can
		* assume its nothing to do with the AAL5 frame
		*/

		if ( (pti&ATM_PTI_OAM_CELL) == ATM_PTI_OAM_CELL ) {
		        report(0, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "Management cell in stream (OAM)\n", src, ATM_CELL_TOTAL_SIZE);
			src    += ATM_CELL_TOTAL_SIZE;
			length -= ATM_CELL_TOTAL_SIZE;
			/* Reset pti because this _could_ be the last cell in the buffer */
			pti = 0;
			continue;
		}

		/* deal with the congestion bit in user-data cell: take it out; data is OK */

		if (pti == 2)  pti = 0;
		if (pti == 3)  pti = 1;

		atm_cell_read(dst, src);

		src      += ATM_CELL_TOTAL_SIZE;
		dst      += ATM_CELL_DATA_SIZE;		
		*cur_pos += ATM_CELL_DATA_SIZE;
		length   -= ATM_CELL_TOTAL_SIZE;

		/*
		* Finally check if we have reached the end
		* of the AAL5 frame
		*/
		if( (pti&ATM_USER_SDU) == ATM_USER_SDU ) {
		        break;
		}

	}

	if(pti != 0 && length > 0)
		*atm_pointer = src;
	else
		*atm_pointer = NULL;

	return(pti);

}

/*
* Function     : aal5_frame_from_atm_cells
* Return value : real size of the rebuilded aal5 frame
* Description  : ...
*/

int aal5_frame_dec(unsigned char *data, unsigned char *frame, int length)
{

	int real_length;
	unsigned int frame_crc, computed_crc;


	/* CRC checking */
	computed_crc = ~aal5_calc_crc(frame, length - 4, ~0);
	frame_crc    = data[length-4]<<24|data[length-3]<<16|data[length-2]<<8|data[length-1];

	/* If not equal the aal5 frame is corrupted */
	if(computed_crc != frame_crc)
		return(-1);

	/* Find the real len */
	real_length = (((int)frame[length - 6])<<8)|((int)frame[length - 5]);

	/* If real > expected length, This is most likely a deliberate crack attempt */
	if(real_length > length)
		return(-2);

	/* Copy the data */
	if(data != frame)
		memmove(data, frame, real_length);

	return(real_length);

}

#endif
