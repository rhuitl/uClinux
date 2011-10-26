/*
 *  cpsel, code page selection cgi
 *  Copyright (c) 1998 Martin Hinner <martin@tdp.cz>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cpsel.config.h"

#define HTML_HEAD		"<html><head><title>"
#define HTML_TITLE	"</title></head><body><center><h1>"
#define HTML_BODY		"</h1></center>"
#define HTML_TAIL		"</body></html>"

#ifdef CZECH
char *body1 = 
HTML_HEAD
"Vyber kodove stranky"
HTML_TITLE
"Vyber kodove stranky"
HTML_BODY
"Vyberte si prosim kodovou stranku, kterou podporuje Vas browser:<p>";

char *body2 =
"<hr>Tato stranka byla vygenerovana programem <em>cpsel</em>.<br>"
"<em>cpsel</em> je cast <a href=\"http://www.boa.org/\">webserveru boa</a>."
HTML_TAIL;

char *body0 = 
"Content-type: text/html\r\n\r\n"
"CPSEL error!";
#endif

int getcgiparam(char *dst,char *query_string,char *param,int maxlen)
{
 int len,plen;
 int y;

 plen=strlen(param);
 while (*query_string)
  {
   len=strlen(query_string);

   if ((len=strlen(query_string))>plen)
    if (!strncmp(query_string,param,plen))
     if (query_string[plen]=='=')
      {//copy parameter
       query_string+=plen+1;
       y=0;
       while ((*query_string)&&(*query_string!='&'))
				{	
				   if ((*query_string=='%')&&(strlen(query_string)>2))
				     if ((isxdigit(query_string[1]))&&(isxdigit(query_string[2])))
				      {
				       if (y<maxlen)
				        dst[y++]=((toupper(query_string[1])>='A'?toupper(query_string[1])-'A'+0xa:toupper(query_string[1])-'0') << 4)
				           + (toupper(query_string[2])>='A'?toupper(query_string[2])-'A'+0xa:toupper(query_string[2])-'0');
				       query_string+=3;
				       continue;
				      }
				   if (*query_string=='+')
				    {
				     if (y<maxlen)
				      dst[y++]=' ';
				     query_string++;
				     continue;
				    }
				   if (y<maxlen)
				    dst[y++]=*query_string;
				   query_string++;
				  }
	      if (y<maxlen) dst[y]=0;
	      return y;
      }
   while ((*query_string)&&(*query_string!='&')) query_string++;
   query_string++;
  }
 if (maxlen) dst[0]=0;
 return -1;
}


int main()
{
	char url[0x100];
	int nocache;

	url[0]=0;	
	nocache=0;
	if (getenv("QUERY_STRING"))
		getcgiparam(url,getenv("QUERY_STRING"),"url",0x100);
	
	if (!url[0])
	{
		nocache=1;
		if (getenv("HTTP_REFERER"))
			strcpy(url,getenv("HTTP_REFERER"));
	}
	
	if (!url[0])
	{
		puts(body0);
		return 0;
	}
	
	puts("Content-type: text/html\r\n");
	if (nocache)
		puts("Pragma: no-cache\r\n");
	puts("\r\n");

	puts(body1);
	
	puts(body2);
	
	return 0;
}
