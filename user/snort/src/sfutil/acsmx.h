/* $Id$ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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
**   ACSMX.H 
**
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ACSMX_H
#define ACSMX_H


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
*   Prototypes
*/


#define ALPHABET_SIZE    256     

#define ACSM_FAIL_STATE   -1     


typedef struct _acsm_pattern {      

    struct  _acsm_pattern *next;
    unsigned char         *patrn;
    unsigned char         *casepatrn;
    int      n;
    int      nocase;
    int      offset;
    int      depth;
    void   * id;
    int      iid;

} ACSM_PATTERN;


typedef struct  {    

    /* Next state - based on input character */
    int      NextState[ ALPHABET_SIZE ];  

    /* Failure state - used while building NFA & DFA  */
    int      FailState;   

    /* List of patterns that end here, if any */
    ACSM_PATTERN *MatchList;   

}ACSM_STATETABLE; 


/*
* State machine Struct
*/
typedef struct {
  
	int acsmMaxStates;  
	int acsmNumStates;  

	ACSM_PATTERN    * acsmPatterns;
	ACSM_STATETABLE * acsmStateTable;

        int   bcSize;
        short bcShift[256];

}ACSM_STRUCT;

/*
*   Prototypes
*/
ACSM_STRUCT * acsmNew ();

int acsmAddPattern( ACSM_STRUCT * p, unsigned char * pat, int n,
          int nocase, int offset, int depth, void *  id, int iid );

int acsmCompile ( ACSM_STRUCT * acsm );

int acsmSearch ( ACSM_STRUCT * acsm,unsigned char * T, int n, 
		  int (*Match)( void * id, int index, void * data ),
                  void * data );

void acsmFree ( ACSM_STRUCT * acsm );

int acsmPrintDetailInfo(ACSM_STRUCT *);

int acsmPrintSummaryInfo();

#endif
