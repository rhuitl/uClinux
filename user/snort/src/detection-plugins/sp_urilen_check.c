/* $Id */
/*  
** Copyright (C) 2005 
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
** along with this program; if nto, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Bosotn, MA 02111-1307, USA.
*/

/*
 * sp_urilen_check.c: Detection plugin to expose URI length to 
 * 			user rules.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"

#include "sp_urilen_check.h"

extern HttpUri UriBufs[URI_COUNT];

void UriLenCheckInit( char*, OptTreeNode*, int );
void ParseUriLen( char*, OptTreeNode* );
int CheckUriLenGT(Packet*, struct _OptTreeNode*, OptFpList*);
int CheckUriLenLT(Packet*, struct _OptTreeNode*, OptFpList*);
int CheckUriLenEQ(Packet*, struct _OptTreeNode*, OptFpList*);
int CheckUriLenRange(Packet*, struct _OptTreeNode*, OptFpList*);

/* Called from plugbase to register any detection plugin keywords.
* 
 * PARAMETERS:	None.
 *
 * RETURNS:	Ntohing.
 */
void 
SetupUriLenCheck()
{
	RegisterPlugin("urilen", UriLenCheckInit );
}

/* Parses the urilen rule arguments and attaches info to 
 * the rule data structure for later use. Attaches detection
 * function to OTN function list.
 * 
 * PARAMETERS: 
 *
 * argp:	Rule arguments
 * otnp:  	Pointer to the current rule option list node
 * protocol:    Pointer specified for the rule currently being parsed	
 *
 * RETURNS:	Nothing.
 */
void 
UriLenCheckInit( char* argp, OptTreeNode* otnp, int protocol )
{
	/* Sanity check(s) */
	if ( !otnp )
		return;

	/* Check if there have been multiple urilen options specified
 	 * in the same rule.
	 */
	if ( otnp->ds_list[PLUGIN_URILEN_CHECK] )
	{
		FatalError("%s(%d): Multiple urilen options in rule\n",
			file_name, file_line );
	}

	otnp->ds_list[PLUGIN_URILEN_CHECK] = 
		(UriLenCheckData*) SnortAlloc(sizeof(UriLenCheckData));

	ParseUriLen( argp, otnp );

}

/* Parses the urilen rule arguments and attaches the resulting
 * parameters to the rule data structure. Based on arguments, 
 * attaches the appropriate callback/processing function
 * to be used when the OTN is evaluated.
 *
 * PARAMETERS:
 *
 * argp:	Pointer to string containing the arguments to be
 *		parsed.
 * otnp:	Pointer to the current rule option list node.
 *
 * RETURNS:	Ntohing.
 */
void
ParseUriLen( char* argp, OptTreeNode* otnp )
{
	UriLenCheckData* datap = NULL;
	char* curp = NULL; 
 	char* cur_tokenp = NULL;
	char* endp = NULL;
	int val;

	/* Get the Urilen parameter block */
	datap = (UriLenCheckData*) 
			otnp->ds_list[PLUGIN_URILEN_CHECK];

	curp = argp;

	while(isspace((int)*curp)) 
		curp++;

	/* Parse the string */
	if(isdigit((int)*curp) && strchr(curp, '<') && strchr(curp, '>'))
	{
		cur_tokenp = strtok(curp, " <>");
		if(!cur_tokenp)
		{

			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		val = strtol(cur_tokenp, &endp, 10);
		if(val < 0 || *endp)
		{
			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		datap->urilen = (unsigned short)val;

		cur_tokenp = strtok(NULL, " <>");
		if(!cur_tokenp)
		{
			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		val = strtol(cur_tokenp, &endp, 10);
		if(val < 0 || *endp)
		{
			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		datap->urilen2 = (unsigned short)val;
		AddOptFuncToList(CheckUriLenRange, otnp );
		return;
	}
	else if(*curp == '>')
	{
		curp++;
		AddOptFuncToList(CheckUriLenGT, otnp);
	}
	else if(*curp == '<')
	{
		curp++;
		AddOptFuncToList(CheckUriLenLT, otnp);
	}
	else
	{
		AddOptFuncToList(CheckUriLenEQ, otnp);
	}

	while(isspace((int)*curp)) curp++;

	val = strtol(curp, &endp, 10);
	if(val < 0 || *endp)
	{
		FatalError("%s(%d): Invalid 'urilen' argument.\n",
	   		file_name, file_line);
	}

	datap->urilen = (unsigned short)val;

	
}


/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise (no match)
 */
int 
CheckUriLenEQ(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{

    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri  ))
    {
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen == 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, return 0 */
    return 0;
}

/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise(no match)
 */
int 
CheckUriLenGT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri ))
    {
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen < 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, return 0 */
    return 0;
}
 
/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise (no match)
 */
int 
CheckUriLenLT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri ))
    {
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen > 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, return 0 */
    return 0;
}

/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise (no match)
 */
int 
CheckUriLenRange(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri ))
    {
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen <= 
		UriBufs[0].length &&
     ((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen2 >= 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    return 0;
}

