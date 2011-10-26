/* Special state for handling include files */
%x src

%{
/*
 * lex_config.l 1.39 2000/06/12 21:33:02
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License
 * at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and
 * limitations under the License. 
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU Public License version 2 (the "GPL"), in which
 * case the provisions of the GPL are applicable instead of the
 * above.  If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use
 * your version of this file under the MPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the GPL.  If you do not delete the
 * provisions above, a recipient may use your version of this file
 * under either the MPL or the GPL.
 */

#undef src
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <glob.h>
#define src 1

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>

#include "yacc_config.h"

/* For assembling nice error messages */
char *current_file;
int current_lineno;

static int lex_number(char *s);
static int lex_string(char *s);
static void do_source(char *fn);
static int do_eof(void);

%}

int	[0-9]+
hex	0x[0-9a-fA-F]+
str	\"([^"]|\\.)*\"

%%

source		BEGIN(src);
<src>[ \t]*	/* skip */ ;
<src>[^ \t\n]+	do_source(yytext); BEGIN(INITIAL);
<<EOF>>		if (do_eof()) yyterminate();

\n		current_lineno++;
[ \t]*		/* skip */ ;
[ ]*[#;].*	/* skip */ ;

anonymous	return ANONYMOUS;
bind		return BIND;
cis		return CIS;
card		return CARD;
class		return CLASS;
default		return DEFAULT;
device		return DEVICE;
dtype		return DTYPE;
exclude		return EXCLUDE;
function	return FUNCTION;
include		return INCLUDE;
irq		return IRQ_NO;
jedec		return JEDEC;
manfid		return MANFID;
memory		return MEMORY;
module		return MODULE;
mtd		return MTD;
needs_mtd	return NEEDS_MTD;
opts		return OPTS;
pci		return PCI;
port		return PORT;
region		return REGION;
reserve		return RESERVE;
to		return TO;
tuple		return TUPLE;
version		return VERSION;

memory_card	return lex_number("1");
serial_port	return lex_number("2");
parallel_port	return lex_number("3");
fixed_disk	return lex_number("4");
video_adapter	return lex_number("5");
network_adapter	return lex_number("6");
aims_card	return lex_number("7");
scsi_adapter	return lex_number("8");

{int}		return lex_number(yytext);

{hex}		return lex_number(yytext);

{str}		return lex_string(yytext);

.		return yytext[0];

%%

#ifndef yywrap
int yywrap() { return 1; }
#endif

/*======================================================================

    Stuff to parse basic data types

======================================================================*/

static int lex_number(char *s)
{
    yylval.num = strtoul(s, NULL, 0);
    return NUMBER;
}

static int lex_string(char *s)
{
    int n = strlen(s);
    yylval.str = malloc(n-1);
    strncpy(yylval.str, s+1, n-2);
    yylval.str[n-2] = '\0';
    return STRING;
}

/*======================================================================

    Code to support nesting of configuration files

======================================================================*/

#define MAX_SOURCE_DEPTH 4
struct source_stack {
    YY_BUFFER_STATE	buffer;
    char		*filename;
    int			lineno, fileno;
    FILE		*file;
    glob_t		glob;
} source_stack[MAX_SOURCE_DEPTH];
static int source_stack_ptr = 0;
static int parse_env = 0;

static int get_glob(void)
{
    struct source_stack *s = &source_stack[source_stack_ptr];
    while (s->fileno < s->glob.gl_pathc) {
	char *fn = s->glob.gl_pathv[s->fileno];
	s->file = fopen(fn, "r");
	if (s->file == NULL) {
	    if (strpbrk(fn, "?*[") == NULL)
		syslog(LOG_INFO, "could not open '%s': %m", fn);
	    s->fileno++;
	} else {
	    current_lineno = 1;
	    current_file = strdup(fn);
	    yy_switch_to_buffer(yy_create_buffer(s->file, YY_BUF_SIZE));
	    source_stack_ptr++;
	    s->fileno++;
	    return 0;
	}
    }
    return -1;
}

static void do_source(char *fn)
{
    struct source_stack *s = &source_stack[source_stack_ptr];

    if (source_stack_ptr >= MAX_SOURCE_DEPTH) {
	syslog(LOG_INFO, "source depth limit exceeded");
	return;
    }
    glob(fn, GLOB_NOCHECK, NULL, &s->glob);
    s->fileno = 0;
    s->buffer = YY_CURRENT_BUFFER;
    s->lineno = current_lineno;
    s->filename = current_file;
    get_glob();
}

static int do_eof(void)
{
    struct source_stack *s = &source_stack[--source_stack_ptr];
    if (source_stack_ptr < 0) {
	if (parse_env == 0) {
	    char *t = getenv("PCMCIA_OPTS");
	    if (t == NULL) return -1;
	    parse_env = 1;
	    source_stack_ptr = 0;
	    current_file = "PCMCIA_OPTS";
	    current_lineno = 1;
	    yy_scan_string(t);
	    return 0;
	} else
	    return -1;
    }
    fclose(s->file);
    free(current_file);
    yy_delete_buffer(YY_CURRENT_BUFFER);
    if (get_glob() != 0) {
	yy_switch_to_buffer(s->buffer);
	current_lineno = s->lineno;
	current_file = s->filename;
    }
    return 0;
}

/*======================================================================

    The main entry point... returns -1 if the file can't be accessed.

======================================================================*/

int parse_configfile(char *fn)
{
    FILE *f;
    
    f = fopen(fn, "r");
    if (!f) {
	syslog(LOG_INFO, "could not open '%s': %m", fn);
	return -1;
    }
    current_lineno = 1;
    current_file = fn;
    source_stack_ptr = 0;
    yyrestart(f);
    yyparse();
    fclose(f);
    return 0;
}

