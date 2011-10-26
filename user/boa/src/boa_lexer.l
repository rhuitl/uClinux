%{

/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
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

#include "y.tab.h"
#include <stdlib.h>
#include <unistd.h>
#include "boa.h"

char *mime_types;           /* this must be dynamic, because it's freed */

static int file = 0;
int lineno = 1;
struct ccommand *k; 
%}

%s MIME
%%

[ \t]+		;
#.*		;

<MIME>[^ \t\n]+\/[^ \t\n]+	{ yylval.sval = yytext; return MIMETYPE; }

[^ \t\n]+	{ /* XXX could use better checks that we are in a state to
		   * accept keywords; this version matches original behavior */
		  if ((YYSTATE==INITIAL) && (k=lookup_keyword(yytext))) {
		      yylval.cval=k;
		      return (k->type);
		  } else { yylval.sval = yytext; return STRING; }
                }

\n		{ lineno++; }
%%

/* In yywrap we track which file we are on.
 * 1: close boa.conf, open mime.types
 * 2: return 1;
 */

int yywrap()
{
    fclose(yyin);
    file++; 

    switch(file) {
      case 1:
	/* printf("Using %s as mime.types file.\n", mime_types); */
	yyin = fopen(mime_types, "r");
	if(!yyin) {
	    fprintf(stderr, "Could not open mime.types file, \"%s\", "
	    	"for reading\n", mime_types);
	    exit(1);
	}
	BEGIN MIME;
	return 0;
      default:
	BEGIN INITIAL;
	file = 0;		/* in case we reread config files */
	return 1;
    }
}

int yyerror(char * msg)
{
    fprintf(stderr, "Error on line %d of %s: %s\n", lineno, 
      (file == 0 ? "boa.conf" : "mime.types"), msg);
    return 1;
}

