/*
 * bmh.h
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
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Marc Norton
 *
 * Date: 5/2005
 *
 * Boyer-Moore-Horsepool for small pattern groups
 *
 */
#ifndef BOYER_MOORE_HORSPOOL
#define BOYER_MOORE_HORSPOOL

#define HBM_STATIC 

typedef struct {

 unsigned char *P;
 unsigned char *Pnc;
 int            M;
 int            bcShift[256];
 int            nocase;
}HBM_STRUCT;



HBM_STATIC HBM_STRUCT    * hbm_prep( unsigned char * pat, int m, int nocase );
HBM_STATIC int hbm_prepx( HBM_STRUCT *p, unsigned char * pat, int m, int nocase );
HBM_STATIC unsigned char * hbm_match( HBM_STRUCT *p, unsigned char * text, int n );
HBM_STATIC void            hbm_free( HBM_STRUCT *p );

#endif
