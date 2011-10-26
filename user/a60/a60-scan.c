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
 * a60-scan.c:						oct '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * The Algol 60 scanner.
 *
 * a big hack includes the scanning of non quoted keywords:
 * 		begin  vprint ("nase")  end
 * this cannot be used within identifiers with white spaces:
 * 	bad: 	begin  integer foo bar; end
 * 	ok:	begin  integer foobar; end
 *
 * so scan_strict is set, if a60_strict is set, or if a quoted begin
 * is found.
 */

#include "comm.h"
#include "a60.h"
#include "util.h"
#include "a60-ptab.h"
#include "a60-scan.h"


/*
 * the linenumber of the scanner; reported as lineno is the last seen
 * line; (delay for the look-ahead-token)
 */

static int scan_lineno;


/*
 * character test and conversion.
 */
#define mischar(c)	(((c) >= 'a' && (c) <= 'z') \
			 || ((c) >= 'A' && (c) <= 'Z'))
#define misdigit(c)	((c) >= '0' && (c) <= '9')
#define misupper(c)	((c) >= 'A' && (c) <= 'Z')
#define mtolower(c)	(misupper(c) ? (c) - 'A' + 'a' : (c))
#define mprintable(c)	((c) >= 32 && (c) <= 126)


/*
 *  forwards:
 */
static int scan_exp ();
static void skip_following_comment ();
static void skip_end_comment ();
static void skip_over_whites ();
static int s_getchar ();
static void s_unput ();


/*
 * error reporting:
 */
static char *yytext;
static int yylen;
static int yyidx;


/*
 * translate a string into a readable ascii form:
 */

static char *
asc_str (s, len)
char *s;
int len;
{
	static char *buf = (char *) 0;
	char *ptr;

	if (len < 0)
		len = strlen (s);

	if (buf) {
		xfree (buf);
		buf = (char *) 0;
	}

	if (! s || ! *s)
		return "EOF";

	/* maximum is a two char escape-sequence for one input char: */
	buf = xmalloc ((long) (2 * strlen (s) + 1));

	for (ptr = buf; len > 0; s++, ptr++, len--) {

		if (*s == '\n')
			*ptr++ = '\\', *ptr = 'n';
		else if (*s == '\r')
			*ptr++ = '\\', *ptr = 'r';
		else if (mprintable (*s))
			*ptr = *s;
		else if (*s == '\0')
			*ptr++ = '^', *ptr = '@';
		else if (*s >= 1 && *s <= 26)
			*ptr++ = '^', *ptr = 'A' + *s - 1;
		else
			*ptr = '.';
	}

	*ptr = 0;

	return buf;
}

/*
 * return a printable string for a single char:
 */

static char *
ch_str (ch)
int ch;
{
	char tmp [1];

	tmp [0] = ch;

	return asc_str (tmp, 1);
}


/*
 * give a readable string of the scanned input.
 */

static char *
s_text (yytext)
char *yytext;
{
	static char *rval = (char *) 0;

	if (rval) {
		xfree (rval);
		rval = (char *) 0;
	}

	rval = xstrdup (asc_str (yytext, -1));

	return rval;
}


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
		yytext [yyidx] = 0;
		a60_error (infname, lineno, "%s (scanned: %s)\n",
			   s, s_text (yytext));
		return;
	}
	a60_error (infname, lineno, "%s\n", s);
}

void
yywarning (s)
char *s;
{
	a60_error (infname, lineno, "warning: %s\n", s);
}


/*
 * the keywords. (they are expected to be enclosed in ').
 */

#define fstrcmp(a, b) \
	(*(a) != *(b) || strcmp (a, b))


static KEYWORD
keywords[] = {

	{ "10",			TTEN },
	{ "and",		TAND },
	{ "array",		TARRAY },
	{ "begin",		TBEGIN },
	{ "boolean",		TBOOL },
	{ "code",		TCODE },
/***	{ "comment",		TCOMMENT }, ***/
	{ "div",		TDIV },
	{ "do",			TDO },
	{ "else",		TELSE },
	{ "end",		TEND },
	{ "equal",		TEQUAL },
	{ "equiv",		TEQUIV },
	{ "false",		TFALSE },
	{ "for",		TFOR },
	{ "goto",		TGOTO },
	{ "greater",		TGREATER },
	{ "if",			TIF },
	{ "impl",		TIMPL },
	{ "integer",		TINTEGER },
	{ "label",		TLABEL },
	{ "less",		TLESS },
	{ "not",		TNOT },
	{ "notequal",		TNOTEQUAL },
	{ "notgreater",		TNOTGREATER },
	{ "notless",		TNOTLESS },
	{ "or",			TOR },
	{ "own",		TOWN },
	{ "pow",		TPOW },
	{ "procedure",		TPROC },
	{ "real",		TREAL },
	{ "step",		TSTEP },
	{ "string",		TSTRING },
	{ "switch",		TSWITCH },
	{ "then",		TTHEN },
	{ "true",		TTRUE },
	{ "until",		TUNTIL },
	{ "value",		TVALUE },
	{ "while",		TWHILE },
	{ "",			0 }
};


/*
 * look for a keyword in the keyword table; if found, return the token,
 * if not found return 0.
 */

static int
get_keyword (s)
char *s;
{
	KEYWORD *kp;
	char *lower_str;
	int i;

	lower_str = xmalloc ((long) strlen (s) + 1);
	for (i = 0; i < strlen (s); i++)
		lower_str [i] = mtolower(s[i]);

	lower_str [i] = 0;

	for (kp = keywords; kp->name && *kp->name; kp++)
		if (! fstrcmp (lower_str, kp->name))
			break;
	
	xfree (lower_str);

	return kp->token;
}


/*
 * the special strings; short constant strings, but no (real) keywords.
 */

#define MAX_SPEC	2	/* maximum length of a special */

static KEYWORD
special [] = {

	{ "+",	'+' },	{ "-",	'-' },
	{ "*",	'*' },	{ "/",	'/' },
	{ ",",	',' },	{ ".",	'.' },
	{ ";",	';' },	{ "(",	'(' },
	{ ")",	')' },	{ ":",	':' },
	{ "[",	'[' },	{ "]",	']' },
	{ "..",	':' },	{ "(/",	'[' },
	{ "/)",	']' },
	{ ">",		TGREATER },
	{ ">=",		TNOTLESS },
	{ "<",		TLESS },
	{ "<=",		TNOTGREATER },
	{ "=",		TEQUAL },
	{ "!=",		TNOTEQUAL },
	{ ":=",		TASSIGN },
	{ ".=",		TASSIGN },
	{ "**",		TPOW },
	{ "^",		TPOW },
	{ "",		0 }
};

/*
 * skip white spaces:
 */

static int skip_white;

/*
 * current linenumber.
 */

int lineno;

/*
 * the input buffer:
 */

static char *inbuf, *ib_ptr;
static int ib_max, ib_len, ib_eof;

/*
 * character test (and conversion). 
 */

static int
is_char (c)
int c;
{
	return mischar(c);
}

static int
is_digit (c)
int c;
{
	return misdigit(c);
}

static int
is_white (c)
int c;
{
	if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
		return 1;

	return 0;
}


/*
 * case insensitive strncmp:
 */

static int 
ci_strncmp (s1, s2, n)
char *s1, *s2;
int n;
{
	if (! s1 && ! s2)
		return 0;
	if (! s1 || ! s2)
		return 1;
	if (n <= 0)
		return 0;

	for (; n > 0; s1++, s2++, n--) {

		if (mtolower(*s1) != mtolower(*s2))
			return 1;
	}
	
	return 0;
}


/*
 * return 10 power n:
 */

double
pow10 (n)
int n;
{
	int rev = 0;
	double result = 1.0;

	if (n < 0) {
		rev = 1;
		n = - n;
	}

	/* hmmmmm - what to do ... */
	if (n > 10000)
		n = 10000;

	while (n > 0) {
		result *= 10.0;
		n = n - 1;
	}

	if (rev)
		return 1.0 / result;
	else 
		return result;
}


/*
 * called one time for initialisation.
 */

void
init_lex ()
{
	int c;

	/*
	 * allocate the input buffer and the error-text buffer (yytext):
	 */

	ib_max = 100;
	inbuf = xmalloc ((long) ib_max);
	ib_len = 0;
	ib_ptr = inbuf;
	ib_eof = 0;

	yytext = xmalloc ((long) 100);
	yylen = 100;
	yyidx = 0;

	scan_lineno = lineno = 1;

	/*
	 * skip leading whites; the following quote decides...
	 */
	
	c = s_getchar ();
	skip_over_whites (c);

	c = s_getchar ();
	if (c == '\'') {
		if (verbose)
			fprintf (stderr, "will scan in strict a60 manner.\n");
		scan_strict = 1;
	}

	s_unput (c);		/* flush back */

	skip_white = scan_strict;
}


static void
expand_inbuf (n)
int n;
{
	int ib_offset = (int) (ib_ptr - inbuf);		/* offset into inbuf */

	ib_max += n;
#ifdef DEBUG
	if (do_debug)
		printf ("++ inbuf expanded to %ld bytes.\n", (long) ib_max);
#endif /* DEBUG */
	inbuf = xrealloc (inbuf, (long) ib_max);

	ib_ptr = inbuf + ib_offset;
}


static void
fill_inbuf (n)
int n;
{
	int c, i;
	char *fill_ptr;

	if (ib_eof)
		return;

	if (ib_ptr != inbuf) {
		/*
		 * cleanup buffer ptr:
		 */

		for (i = 0; i < ib_len; i++)
			inbuf [i] = ib_ptr [i];
		ib_ptr = inbuf;
	}

	fill_ptr = ib_ptr + ib_len;

	for (i = 0; i < n; i++) {

		if (ib_ptr + ib_len + 2 >= inbuf + ib_max)
			expand_inbuf (n + 10);

		c = fgetc (infile);

		if (c == EOF) {
			ib_eof = 1;
			break;
		}
		else {
			*fill_ptr++ = c;
			ib_len++;
		}
	}
}


/*
 * return the next input character; return 0 at eof.
 * skip whites, if skip_white == 1;
 */

static int
s_getchar ()
{
	int c = 0;

	for (;;) {

		if (! ib_eof && ib_len == 0)
			fill_inbuf (1);

		if (ib_eof && ib_len == 0)
			return 0;

		ib_len--;
		c = *ib_ptr;
		ib_ptr++;

		if (is_white (c)) {
			if (c == '\n')
				scan_lineno++;
			if (! skip_white)
				break;
		}
		else
			break;
	}

	if (yyidx + 2 >= yylen) {
		yylen += 100;
		yytext = xrealloc (yytext, (long) yylen);
	}
	yytext [yyidx++] = c;

#ifdef DEBUG
	if (do_debug) {
		printf ("++ s_getchar: next one: `%s'   (scan_lineno %d)\n",
			ch_str (c), scan_lineno);
	}
#endif

	return c;
}


static void
s_unput (c)
int c;
{
	int i;

	/* expand about 2 or 3 characters ... (don't care)
	   one for the unget char and one for a trailing '\0'
	   (better for debugging) */

	if (ib_ptr + ib_len + 3 >= inbuf + ib_max)
		expand_inbuf (3);

	if (ib_ptr == inbuf) {
		/*
		 * shift one char to right.
		 * (the + 1 is for a trailing 0)
		 */
		for (i = ib_len + 1; i > 0; i--)
			inbuf [i] = inbuf [i-1];
		ib_ptr++;
	}

	ib_len++; ib_ptr--;
	*ib_ptr = c;

	if (yyidx > 0)
		yyidx--;

	if (c == '\n')
		scan_lineno--;

#ifdef DEBUG
	if (do_debug) {
		printf ("++ s_unput (%c): ib_len %d ; ib now `", c, ib_len);
		for (i = 0; i < ib_len; i++)
			printf ("%c", ib_ptr [i]);
		printf ("' - honk.\n");
	}
#endif /* DEBUG */
}


/*
 * scan a whitespace;
 */

static int
scan_white (c)
int c;
{
	return is_white (c);
}


/*
 * skip over whites;
 */

static void
skip_over_whites (c)
int c;
{
	while (is_white (c))
		c = s_getchar ();
	
	s_unput (c);
}


/*
 * still scanned a quote ('); look for keyword.
 * no keyword is longer than 10 chars ('notgreater'). lets scan max
 * 20 chars for some context in the yytext string.
 */

static int
scan_keyword ()
{
#define KW_MAX	20
	char keyw [KW_MAX];
	int kw_len = 0, kwt, c;

#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for keyword ...\n");
#endif /* DEBUG */

	while ((c = s_getchar ()) != 0) {

		if (scan_white (c))
			continue;

		if (c == '\'')
			break;

		if (kw_len + 2 >= KW_MAX)
			break;

		keyw [kw_len++] = c;
	}

	keyw [kw_len] = 0;

	kwt = get_keyword (keyw);

	/*
	 * reported (hopefully) by parser-module:
	 *
	 * if (! kwt) {
	 *	yyerror ("unknown keyword");
	 * }
	 */ 
	
#ifdef DEBUG
	if (do_debug)
		printf ("++ got %d from `%s'\n", kwt, keyw);
#endif /* DEBUG */

	if (kwt == TBEGIN)
		skip_following_comment ();

	if (kwt == TEND)
		skip_end_comment (1);			/* quotes active */

	return kwt;
}


static int
scan_string ()
{
	static int st_max = 0;
	static char *str;
	int st_len = 0, c, level = 1, krach = 0;
	
#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for string ...\n");
#endif /* DEBUG */

	skip_white = 0;

	while ((c = s_getchar ()) != 0) {

		if (! krach && (c == '\'' || c == '"'))
			level--;
		else if (! krach && c == '`')
			level++;

		if (! level)
			break;

		if (st_len + 2 >= st_max) {
			st_max += 10;
			if (! str)
				str = xmalloc ((long) st_max);
			else
				str = xrealloc (str, (long) st_max);
		}
		if (krach) {
			if (c == 'n')		c = '\n';
			else if (c == 't')	c = '\t';
			else if (c == '"')	c = '"';
			else if (c == '\'')	c = '\'';
			else if (c == '`')	c = '`';
			str [st_len++] = c;
			krach = 0;
		}
		else if (c == '\\')
			krach = 1;
		else
			str [st_len++] = c;
	}

	str [st_len] = 0;

#ifdef DEBUG
	if (do_debug)
		printf ("++ found `%s'.\n", str);
#endif /* DEBUG */

	skip_white = scan_strict;

	yylval.str = xstrdup (str);

	return STRING;
}


static int
scan_identifier (ch)
int ch;
{
	static int id_max = 0;
	static char *ident;
	int id_len = 0, c;
	
#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for identifier ...\n");
#endif /* DEBUG */

	s_unput (ch);

	while ((c = s_getchar ()) != 0) {

		if (is_white (c)) {
			if (skip_white)
				continue;
			else {
				skip_over_whites (c);
				break;
			}
		}
		if (! is_char (c) && ! is_digit (c)) {
			s_unput (c);
			break;
		}

		if (id_len + 2 >= id_max) {
			id_max += 10;
			if (! ident)
				ident = xmalloc ((long) id_max);
			else
				ident = xrealloc (ident, (long) id_max);
		}
		ident [id_len++] = c;
	}

	ident [id_len] = 0;

#ifdef DEBUG
	if (do_debug)
		printf ("++ found `%s'.\n", ident);
#endif /* DEBUG */

	if (! scan_strict) {
		/* how to parse:  begin integer a nase; end */

		/*
		 * if the string is a keyword, then return the keyword-token
		 */
		
		int kwt = get_keyword (ident);
		if (kwt) {

			if (kwt == TBEGIN)
				skip_following_comment ();

			if (kwt == TEND)
				skip_end_comment (0);

			return kwt;
		}
	}
	
	/* found an identifier: */

	yylval.str = xstrdup (ident);

	return NAME;
}


/*
 * scan the fractional part; num is the full (sp?) part.
 */

static int 
scan_frac (num)
long num;
{
	double rval = num;
	double frac = 0, pot = 10;
	int c;

	while (is_digit (c = s_getchar ())) {
		frac = frac + (c - '0') / pot;
		pot = pot * 10;
	}

	if (c == 'e' || c == 'E')
		return scan_exp (rval + frac);


	/* ok - still scanned a real value: */

#ifdef DEBUG
	if (do_debug)
		printf ("++ got real %e\n", (double) rval + frac);
#endif /* DEBUG */

	s_unput (c);

	yylval.rtype = rval + frac;

	return RNUM;
}


/*
 * scan the exponential part; if it is expressed as X '10' Y its done in
 * a60-parse.y; here a additional form X e Y (or X E Y) is scanned.
 */

static int
scan_exp (num)
double num;
{
	double rval = num;
	int rsign = 1;
	int exp_val = 0, c;

	c = s_getchar ();

	if (c == '+') {
		c = s_getchar ();
	}
	else if (c == '-') {
		rsign = -1;
		c = s_getchar ();
	}

	if (! is_digit (c)) {
		a60_error (infname, lineno, "malformed exponent.\n");
	}
	else {
		/* scan the exponent : */
		
		do {
			exp_val = 10 * exp_val + c - '0';
		} while (is_digit (c = s_getchar ()));
		
		rval = rval * pow10 (rsign * exp_val);
	}


#ifdef DEBUG
	if (do_debug)
		printf ("++ got real %e\n", (double) rval);
#endif /* DEBUG */

	s_unput (c);

	yylval.rtype = rval;

	return RNUM;
}


/*
 * here we have a dot or a digit:
 */

static int
scan_number (ch)
int ch;
{
	int c;
	long ival = 0;
	
#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for number...\n");
#endif /* DEBUG */

	if (ch == '.')
		return scan_frac ((long) 0);

	s_unput (ch);

	while (is_digit (c = s_getchar ()))
		ival = 10 * ival + c - '0';

	if (c == '.')
		return scan_frac ((long) ival);

	if (c == 'e' || c == 'E')
		return scan_exp ((double) ival);
	
	/* ok - still scanned a integer value: */

#ifdef DEBUG
	if (do_debug)
		printf ("++ got integer %ld\n", (long) ival);
#endif /* DEBUG */

	s_unput (c);

	yylval.itype = ival;

	return INUM;	
}



/*
 * handle this unknown char; skip input til end-of-line.
 */

void
skip_unknown (ch)
int ch;
{
	static int last_line = -1;
	
	if (last_line == lineno)
		return;
	else
		last_line = lineno;

#if 0
	if (yyidx)
		yytext [yyidx] = 0;

	if (mprintable(ch)) {

		if (yyidx)
			a60_error (infname, lineno,
				"unknown char `%c' found (scanned: %s).\n",
				ch, yytext);
		else
			a60_error (infname, lineno,
				"unknown char `%c' found.\n", ch);
	}
	else {
		if (yyidx)
			a60_error (infname, lineno,
				"unknown char 0x%02x found (scanned: %s).\n",
				ch, yytext);
		else
			a60_error (infname, lineno,
				"unknown char 0x%02x found.\n", ch);
	}
#else
	yyerror ("syntax error");
#endif
	a60_error (infname, lineno, "  [ skipping to next line ]\n");

	nerrors++;

	skip_white = 0;

	do {
		ch = s_getchar ();
	} while (ch && ch != '\n');

	skip_white = scan_strict;
}


/*
 * we've found a ';' or a 'begin'; now look about a following comment
 * and skip, if found, to the next semicolon.
 */

static void
skip_following_comment ()
{
	char *str = xmalloc ((long) 100);
	long str_max = 100;
	int str_len = 0, quoted_comment = 0;
	int c;

#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for 'comment'...\n");
#endif /* DEBUG */

	c = s_getchar ();

	if (! scan_strict) {
		skip_over_whites (c);
		c = s_getchar ();
	}

	quoted_comment = (c == '\'');

	if (scan_strict && ! quoted_comment) {
#ifdef DEBUG
		if (do_debug)
			printf ("++ no 'comment'.\n");
#endif /* DEBUG */
		s_unput (c);
		return;
	}

	do {
		if (str_len + 2 >= str_max) {
 			str_max += 100;
			str = xrealloc (str, str_max);
		}
		str [str_len++] = c; /*** mtolower (c); ***/
		c = s_getchar ();

		if (! c)
			break;

	} while ((quoted_comment && c != '\'')
		 || (! quoted_comment && c != 't'
		     && str_len != 6 && ci_strncmp ("commen", str, 6)));

	str [str_len++] = c;
	str [str_len] = '\0';
	
#ifdef DEBUG
	if (do_debug)
		printf ("++ examining `%s'...\n", asc_str (str, -1));
#endif /* DEBUG */

	if ((quoted_comment && ! ci_strncmp (str+1, "comment", 7))
	    || ! ci_strncmp ("comment", str, 7)) {
		/*
		 * well done; skip anything til a ';':
		 */
#ifdef DEBUG
		if (do_debug)
			printf ("++ skipping 'comment': `");
#endif /* DEBUG */
		while ((c = s_getchar ()) != ';') {
#ifdef DEBUG
			if (do_debug)
				printf ("%s", ch_str (c));
#else /* ! DEBUG */
			continue;
#endif /* ! DEBUG */
		}

#ifdef DEBUG
		if (do_debug)
			printf ("' skipped.\n");
#endif /* DEBUG */

		/*
		 * now do this again...
		 */
		xfree (str);
		skip_following_comment ();
		return;
	}
	else {
		/* 
		 * no comment; unget and forget:
		 */
#ifdef DEBUG
		if (do_debug)
			printf ("++ forgetting `%s'...\n", 
				asc_str (str, str_len));
#endif /* DEBUG */
		while (str_len > 0)
			s_unput (str [--str_len]);		

		xfree (str);	
	}
}


/*
 * scan the end of the string for and 'end' delimiter: 'end' or 'else'
 * or ';'; return an ptr to the first char.
 */

static char *
end_delim (str, str_len, quoted_comment)
char *str;
int str_len;
int quoted_comment;
{
	static char *e_delim [4];
	char **ptr, *str_ptr;

	e_delim [0] = ";";
	if (quoted_comment)
		e_delim [1] = "'end'",	e_delim [2] = "'else'";
	else
		e_delim [1] = "end",	e_delim [2] = "else";
	e_delim [3] = "";

#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for end_delim in `%s': ", str);
#endif /* DEBUG */
 
	for (ptr = e_delim; ptr && *ptr && **ptr; ptr++) {
		str_ptr = str + str_len - strlen (*ptr);
		if (str_ptr >= str && 
		    ! strncmp (str_ptr, *ptr, strlen (*ptr))) {
#ifdef DEBUG
			if (do_debug)
				printf (" found %s.\n", *ptr);
#endif /* DEBUG */
			return str_ptr;
		}
	}

#ifdef DEBUG
	if (do_debug)
		printf (" not found.\n");
#endif /* DEBUG */

	return (char *) 0;
}


/*
 * got a 'end'; now skip anything until 'end' or 'else' or ';':
 */

static void
skip_end_comment (quoted_comment)
int quoted_comment;
{
	char *str = xmalloc ((long) 10);
	long str_max = 10;
	int str_len = 0;
	char *end_str = str, *ptr;
	int c;

#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for 'end' comment...\n");
#endif /* DEBUG */

	while ((c = s_getchar ()) != 0) {

		if (str_len + 2 >= str_max) {
 			str_max += 10;
			str = xrealloc (str, str_max);
		}
		str [str_len++] = mtolower (c);
		str [str_len] = 0;

		end_str = end_delim (str, str_len, quoted_comment);
		if (end_str)
			break;
	}

#if 0
	if (! c && str_len > 0) {
		yyerror ("EOF reached within 'end' ...");
	}
	else
#endif
	{
		str [str_len] = 0;

		if (end_str) {
#ifdef DEBUG
			if (do_debug)
				printf ("++ found behind 'end': `%s'\n",
					asc_str (str, str_len));
#endif /* DEBUG */
			for (ptr = str+str_len-1; ptr >= end_str; ptr--)
				s_unput (*ptr);
		}
	}
}


/*
 * scan a special; two or one char long.
 */

static int
scan_special (ch)
int ch;
{
	KEYWORD *kw;
	char str [MAX_SPEC+1];
	int i, tok, max_spec_len;

	str [0] = ch;

	for (i=1; i<MAX_SPEC; i++) {
		str [i] = s_getchar ();
		if (is_white (str [i])) {
			s_unput (str [i]);
			break;
		}
	}
	str [i] = '\0';
	max_spec_len = i;

#ifdef DEBUG
	if (do_debug)
		printf ("++ looking for special `%s'...\n", str);
#endif /* DEBUG */

	for (i = max_spec_len; i > 0; i--) {
		for (kw = special; kw->name && *kw->name; kw++) {
			if (! strncmp (kw->name, str, i)) {
				tok = kw->token;
#ifdef DEBUG
				if (do_debug)
					printf ("++ got special %d\n", tok);
#endif /* DEBUG */
				if (tok == ';')
					skip_following_comment ();
				return tok;
			}
		}
		if (i > 1)
			s_unput (str [i-1]);
	}

	/* Oops - what to do... */

	if (! str [0])
		return 0;

	skip_unknown (str[0]);

	return yylex ();
}


/*
 * the common yylex entry;
 * return's the token number or 0 on end of file
 */

int
yylex ()
{
	static int last_scan_lineno = 1;
	int ch, tok;

	yyidx = 0;

	if (ib_eof && ib_len == 0) {
#ifdef DEBUG
		if (do_debug)
			printf ("+++ EOF reached...\n");
#endif /* DEBUG */
		return 0;
	}

	ch = s_getchar ();

	if (! scan_strict) {
		skip_over_whites (ch);
		ch = s_getchar ();
	}

	if (ch == '\'')
		tok = scan_keyword ();
	else if (ch == '`' || ch == '"')
		tok = scan_string ();
	else if (is_char (ch))
		tok = scan_identifier (ch);
	else if (is_digit (ch) || ch == '.')
		tok = scan_number (ch);
	else if (ch)
		tok = scan_special (ch);
	else
		tok = 0;

#ifdef DEBUG
	if (do_debug) {
		if (tok >= 0 && tok <= 256)
			printf ("+++ yylex: returnig token %d (`%s')\n",
				tok, ch_str (tok)); 
		else
			printf ("+++ yylex: returnig token %d\n", tok);
	}
#endif /* DEBUG */

	lineno = last_scan_lineno;
	last_scan_lineno = scan_lineno;

	return tok;
}

/* end of a60-scan.c */

