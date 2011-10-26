/*
    Copyright (C) 2002-2005  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.
    
    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    
    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/


/* $Id: rewrite_rules.h,v 1.6 2005/01/08 10:05:12 hb9xar Exp $ */

/*
 * SIP Method 'knowledg base'
 * This table tells siproxd what incomming requests (which methods)
 * it shell rewite and which not. E.g. kphone behaves silly
 * if a incoming SUBSCRIBE request is rewritten to the local host...
 */
static struct {
   char *UAstring;
   int  action[12];
} RQ_rewrite[] =
{
/*
1 means: rewrite, 0 means don't rewrite, -1 means default
  UA string	  I   A   R   B   O   I   C   R   N   S   M   P
                  N   C   E   Y   P   N   A   E   O   U   E   R
                  V   K   G   E   T   F   N   F   T   B   S   A
                  I       I       I   O   C   E   I   S   S   C
                  T       S       O       E   R   F   C   A   K
                  E       T       N       L       Y   R   G    
*/
{"oSIP/Linphone",{-1, -1, -1, -1, -1, -1. -1, -1, -1, -1, -1, -1}},
{"Windows RTC",	 {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}},
{"KPhone",	 {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}},
/* the following line holds the default entries */
{NULL,		 { 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1}}
};

static struct {
   char *name;
   int  size;
} RQ_method[] = {
{ "INVITE",	6 },
{ "ACK",	3 },
{ "REGISTER",	8 },
{ "BYE",	3 },
{ "OPTIONS",	7 },
{ "INFO",	4 },
{ "CANCEL",	6 },
{ "REFER",	5 },
{ "NOTIFY",	6 },
{ "SUBSCRIBE",	9 },
{ "MESSAGE",	7 },
{ "PRACK",	5 },
{ NULL,		0 }
};
