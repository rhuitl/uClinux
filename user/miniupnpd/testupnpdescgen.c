/* $Id: testupnpdescgen.c,v 1.1 2007-12-27 05:33:40 kwilson Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdlib.h>
#include <stdio.h>

#include "upnpdescgen.h"

char uuidvalue[] = "uuid:12345678-0000-0000-0000-00000000abcd";
char serialnumber[] = "12345678";
char modelnumber[] = "1";
char presentationurl[] = "http://192.168.0.1:8080/";

/* To be improved */
int
xml_pretty_print(const char * s, int len, FILE * f)
{
	int n = 0, i;
	int elt_close = 0;
	int c, indent = 0;
	while(len > 0)
	{
		c = *(s++);	len--;
		switch(c)
		{
		case '<':
			if(len>0 && *s == '/')
				elt_close = 1;
			else
			{
				fputc('\n', f); n++;
				for(i=indent; i>0; i--)
					fputc(' ', f);
				n += indent;
			}
			fputc(c, f); n++;
			break;
		case '>':
			fputc(c, f); n++;
			if(elt_close)
			{
				/*fputc('\n', f); n++; */
				elt_close = 0;
				if(indent > 0)
					indent--;
			}
			else
				indent++;
			break;
		default:
			fputc(c, f); n++;
		}
	}
	return n;
}

int
main(int argc, char * * argv)
{
	char * rootDesc;
	int rootDescLen;
	char * s;
	int l;
	rootDesc = genRootDesc(&rootDescLen);
	xml_pretty_print(rootDesc, rootDescLen, stdout);
	free(rootDesc);
	printf("\n-------------\n");
	s = genWANIPCn(&l);
	xml_pretty_print(s, l, stdout);
	free(s);
	printf("\n-------------\n");
	s = genWANCfg(&l);
	xml_pretty_print(s, l, stdout);
	free(s);
	printf("\n-------------\n");
	return 0;
}

