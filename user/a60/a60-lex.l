%{
/*
 * Copyright (C) 1991,1992 Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * This file is part of NASE A60.
 * 
 * NASE A60 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * NASE A60 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NASE A60; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * a60-lex.l:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * this part is obsolete and replaced by a60-scan.[ch]
 * if you like to use this, complete the keyword scanning (only
 * 'begin' and 'end' are enclosed)
 */

/*
 * special for including "comm.h" :
 */
#define THIS_IS_A60_LEX
#include "comm.h"
#undef THIS_IS_A60_LEX

#include "a60.h"
#include "util.h"
/*
 * this should be ``a60-parse.tab.h'' but there are some systems ...
 * so the names are still short...
 */
#include "a60-ptab.h"


/*
 * better use ctype.h ...
 */
#define misupper(c)	((c) >= 'A' && (c) <= 'Z')
#define mtolower(c)	((c) - 'A' + 'a')

/* current line number. */
int lineno;

/*
 * flex vs. lex:
 */
#ifdef FLEX_SCANNER

/* forwards: */
static int input();
extern FILE *yyin;

#else /* ! FLEX_SCANNER */

/* forwards: */
static int yywrap ();

#endif /* ! FLEX_SCANNER */


#ifdef lint
/* if they use it - i'll provide it: */
extern _flsbuf ();
#endif


/*
 * initalize lex-module.
 */
void
init_lex ()
{
	lineno = 1;

	yyin = infile;
}


/*
 * scan the real number from the buffer and return them.
 */

static double
scan_real (s)
char *s;
{
	char *fmt = "%le";
	double x;

#ifdef pyr
        fmt = "%lf";
#endif

        if (sscanf (s, fmt, &x) < 1) {
		a60_error (infname, lineno,
		   "INTERNAL: cannot scan from `%s'\n", s);
		xabort ("INTERNAL ERROR");
	}

	if (do_debug)
		printf ("** do_scan_real: `%s' -> %.10g\n", s, x);

	return x;
}


/*
 * convert the scanned string from c-like notation.
 */

static char *
scan_string (s)
char *s;
{
	int i, len;
	char *tmp, *ptr;

	len = strlen(s);
	tmp = NTALLOC(len - 1, char);

	if (*s == '\'')
		s += 2, len -= 4;

	for (i=1, ptr=tmp; i < len-1; i++, ptr++) {
		if (s[i] == '\\') {
			i++;
			if (s[i] == 'n')
				*ptr = '\n';
			else if (s[i] == '\\')
				*ptr = '\\';
			else if (s[i] == '\0')
				break;
			else
				*ptr = s[i];
		}
		else
			*ptr = s[i];
	}
	*ptr = '\0';

	return tmp;
}


/*
 * handle this unknown char; skip input til end-of-line.
 */

void
handle_unknown (ch)
int ch;
{
	static int last_line = -1;
	
	if (last_line == lineno)
		return;
	else
		last_line = lineno;

	if (ch >= ' ' && ch <= 'Z')
		 a60_error (infname, lineno,
		    "unknown char `%c' found - skipping to next line\n",
			    ch);
	else
		a60_error (infname, lineno,
		   "unknown char 0x%02x found - skipping to next line\n",
			   ch);
	nerrors++;

	do {
		ch = input();
	} while (ch && ch != '\n');

	lineno++;
}

/* onk. */

%}

%e 2000
%p 3000

word		[a-zA-Z][a-zA-Z0-9 ]*

string		`[^']*'|"'('"[^']*"')'"|\"[^"]*\"

uint		[0-9][0-9]*

ureal		{uint}"."{uint}|"."{uint}

white		" "|"\t"|"\f"|"\r"|"\n"

single		"+"|"-"|"*"|"/"|","|"."|";"|"("|")"

%%

'begin'				return TBEGIN;
'10'				return TTEN;

'end'				return TEND;

{single}			return *yytext;

":"|".."			return ':';
";"|".,"			return ';';
"["|"(/"			return '[';
"]"|"/)"			return ']';
"**"				return TPOW;
":="|".="			return TASSIGN;

"<" 				return TLESS;
">" 				return TGREATER;
"="				return TEQUAL;
"<=" 				return TNOTGREATER;
">="				return TNOTLESS;

{white}*			{ char *s = (char *) yytext;
				  for (; *s; s++)
					  lineno += (*s == '\n');
			  	}

{string}			{ yylval.str = scan_string (yytext);
                                  return STRING;
				}

{ureal}				{  yylval.rtype = scan_real (yytext);
				   return RNUM;
				}

{uint}				{ extern long atol ();
				  yylval.itype = atol (yytext);
				  return INUM;
				}

{word}				{ char *str = xstrdup ((char *) yytext);
				  yylval.str = str;
				  return NAME;
				}

^#!.*				{ if (lineno != 1)
					  yywarning ("directive ignored");
			        }

.				handle_unknown (*yytext & 0xff);

%%


/*
 * error reporting:
 */

void
yyerror(s)
char *s;
{
	nerrors++;
	/*
	 * if there is a ``parse error'' or a ``syntax error''
	 * reported from the skeleton, print the scanned string too.
	 */
	if (! strcmp (s, "parse error")
	    || ! strcmp (s, "syntax error")) {
		a60_error (infname, lineno, "%s (scanned `%s')\n",
			   s, (yytext && *yytext) ? (char *) yytext : "EOF");
		return;
	}
	a60_error (infname, lineno, "%s\n", s);
}

void
yywarning(s)
char *s;
{
	a60_error (infname, lineno, "warning: %s\n", s);
}


#ifndef FLEX_SCANNER

/*
 * EOF is real EOF.
 */
static int
yywrap()
{
	return 1;
}

#endif /* ! FLEX_SCANNER */

/* end of a60-lex.l */
