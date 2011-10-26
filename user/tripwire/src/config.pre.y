%token COMMENT	
%token EOL
%token STRING
%token INCLUDE
%token DEFINE
%token UNDEF
%token ELSE
%token ENDIF
%token CONTENTS
%token DBASEVERSION
%token LPAREN
%token RPAREN
%token ANDAND
%token OROR
%token ECHOTHIS
%token BSLASH
%token ESCCHAR

%{
/* $Id: config.pre.y,v 1.23 1994/08/04 03:44:32 gkim Exp $ */

/*
 * config.y
 *
 *	tw.config preprocessor parser for yacc.
 *
 *	This implementation does an unfortunately large number of 
 *	malloc()'s and free()'s to store the lexeme values.  Although
 *	memory leaks are few, too much time is spent doing memory
 *	allocation.
 *
 *	At this point, I would argue that this is not too significant,
 *	since we only run this routine once.
 *
 * Gene Kim
 * Purdue University
 * October 5, 1992
 *
 * Modified by Cal Page to work with linux, March 9, 1994
 */

#include "../include/config.h"
#include <stdio.h>
#ifdef STDLIBH
#include <stdlib.h>
#endif
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef MALLOCH
#include <malloc.h>
#endif
#include <assert.h>
#include <sys/param.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/list.h"
#include "../include/tripwire.h"

extern FILE *yyin;
extern FILE *yyout;

#ifndef EMBED
#ifdef TW_LINUX
#include <malloc.h>

	void *yy_flex_realloc(void *x,int y) { return realloc(x,y); }
	void *yy_flex_alloc  (int y        ) { return malloc(y);    }
        void yy_flex_free    (void *x      ) { free(x); }

#define yy_strcpy(a,b) strcpy((a),(b))

#endif /* TW_LINUX */
#endif

#define INCLUDE_STACK_SZ 	16	/* max num of nested includes */

int yaccdebuglevel = 0;

static int linenumber = 1;

static FILE *fp_stack[INCLUDE_STACK_SZ];
static int linenumber_stack[INCLUDE_STACK_SZ];
static char *filename_stack[INCLUDE_STACK_SZ];
static int stackpointer = 0;
static int found_db_version = 0;
static struct list **pp_entry_list_global = NULL;

static char currparsefile[MAXPATHLEN+1024];

/* prototypes */
static char *string_dequote();
static void include_push();
static FILE *include_pop();

/* this is for some versions of flex and bison, who don't make any
 * effort to look like lex and yacc.
 */

#ifdef LINUX
extern FILE **yyin, *yyout;
void *yy_flex_realloc(void *x,int y) { return realloc(x,y); }
void *yy_flex_alloc  (int y        ) { return malloc(y); }
void  yy_flex_free   (void *x      ) { free(x); }
#endif

struct comp {
    char *string;
    int directive;
};

%}

%union {
    struct comp *comp;
    char 	*string;
    long 	val;
}

%left <string> COMMENT ESCCHAR STRING
%token <val> IFDEF IFNDEF IFHOST IFNHOST
/*
%type <string> word words directive colines coline else 
*/
%type <comp> word
%type <string> words directive colines coline else 
%type <val> if_expr host_expr
%left <val> ANDAND OROR

%start lines
%%

lines	: lines line 
	| 
	;

/* we do all of the line-emitting in this production (line) */

line	: directive EOL
	    {
		/*
		linenumber++;
		*/

		if ($1)	{ 
		    fprintf(yyout, "%s\n", $1); 
		    free($1);
		}
	    }
	| words EOL
	    {
		/*
		linenumber++; 
		*/

		if ($1)	{ 
		    fprintf(yyout, "%s\n", $1); 
		    free($1);
		}
	    }
	;


colines	: colines coline 
	    {
	    	/* If coline is null, just pass on colines. */
	    	if ($2 == NULL) {
		    $$ = $1;
		} else {
		    /* concatenate the two terminals together */
		    if ($1 == NULL) {
			$$ = (char *) malloc((unsigned) strlen($2) + 1);
			$$[0] = '\0';
		    }
		    else {
			$$ = (char *) malloc((unsigned) 
					    (strlen($1) + strlen($2)) + 2);
			(void) strcpy($$, $1);
			(void) strcat($$, "\n");
    
			/* free up the left component */
			free($1);
		    }
		    (void) strcat($$, $2);
    
		    /* free up the right component */
		    if ($2)
			free($2);
		}
		SPDEBUG(11) printf("--(coline)--> (%s)\n", $$);
	    }
	| 
	    {
		$$ = NULL;
	    }
	;

coline	: directive EOL 		{ $$ = $1; /* linenumber++; */}
	| words EOL 			{ $$ = $1; /* linenumber++; */}
	;

else	: ELSE colines 
	    {
		$$ = $2;
	    }
	| 
	    {
		$$ = NULL;
	    }
	;

if_expr	: LPAREN if_expr RPAREN
	    { 
		$$ = $2;
	    }
	| if_expr ANDAND if_expr
	    {
		$$ = $1 && $3;
	    }
	| if_expr OROR if_expr
	    {
		$$ = $1 || $3;
	    }
	| word
	    {
		check_varname($1->string);
		$$ = tw_mac_ifdef($1->string);
	    }

host_expr: LPAREN host_expr RPAREN
	    { 
		$$ = $2;
	    }
	| host_expr ANDAND host_expr
	    {
		$$ = $1 && $3;
	    }
	| host_expr OROR host_expr
	    {
		$$ = $1 || $3;
	    }
	| word
	    {
		$$ = tw_mac_ifhost($1->string);
	    }

directive:	
	  DEFINE word 		
	    {	
		check_varname($2->string);
	   	tw_mac_define($2->string, ""); 
	        $$ = NULL; 
	    }
	| DEFINE word word 		
	    { 
		check_varname($2->string);
		tw_mac_define($2->string, $3->string); $$ = NULL; 
	    }

	| UNDEF word 			{ 
		check_varname($2->string);
		tw_mac_undef($2->string); $$ = NULL; }
	| IFDEF if_expr
	    {
		$1 = $2;
	    }
          EOL colines else ENDIF
	    {
		if ($1) { $$ = $5; }
		else 	{ $$ = $6; }

		/*
		linenumber++;
		*/
	    }
	| IFNDEF if_expr
	    {
		$1 = !$2;
	    }
          EOL colines else ENDIF
	    {
		if ($1) { $$ = $5; }
		else 	{ $$ = $6; }

		/*
		linenumber++;
		*/
	    }
	| IFHOST host_expr
	    {
		$1 = $2;
	    }
          EOL colines else ENDIF
	    {
		if ($1) { $$ = $5; }
		else 	{ $$ = $6; }

		/*
		linenumber++;
		*/
	    }
	| IFNHOST host_expr
	    {
		$1 = !$2;
	    }
          EOL colines else ENDIF
	    {
		if ($1) { $$ = $5; }
		else 	{ $$ = $6; }

		/*
		linenumber++;
		*/
	    }
	| INCLUDE word
	    {
		/* push a new @@include file onto the include stack */
		include_push($2->string, &yyin);
		$$ = NULL;

	    }
	| CONTENTS word
	    {
		char *pc = "@@contents ";

		/* record contents in list */
		list_set($2->string, "", 0, pp_entry_list_global);

		/* reconstruct and emit the entire string */
		$$ = (char *) malloc((unsigned) (strlen($2->string) + strlen(pc)) + 1);
		(void) strcpy($$, pc);
		(void) strcat($$, $2->string);

		/* free up the right side */
		free($2->string);
		free($2);
	    }
	| ECHOTHIS words
	    {
		fprintf(stderr, "tw.config: echo: %s\n", $2);
		$$ = NULL;
	    }
	| DBASEVERSION word
	    {
		int version;

		if (sscanf($2->string, "%d", &version) != 1) {
		    yyerror("");
		}

		/* check if the database format is too old */
		if (version != db_version_num) {
		    fprintf(stderr, 
"error: database format %d is no longer supported!\n\tSee tw.config(5) manual page for details)\n\t'%s' (expecting version %d)!\n",
			version, currparsefile, db_version_num);
		    exit(1);
		}

		/* free up the right side */
		free($2->string);
		free($2);

		/* we must see one of these productions in the file */
		found_db_version = 1;

		$$ = NULL;
	    }
	;

words	: words word
	    {
		/* concatenate the two terminals together */
		if ($1 == NULL) {
		    $$ = (char *) malloc((unsigned) strlen($2->string) + 1);
		    $$[0] = '\0';
		}
		else {
		    $$ = (char *) malloc((unsigned) 
				(strlen($1) + strlen($2->string)) + 2);
		    (void) strcpy($$, $1);
		    /* XXX: This doesn't work!
		    if ($2 && (!$2->directive))
		    */
		    if ($2)
			(void) strcat($$, " ");

		    /* free up the left component */
		    free($1);
		}
		(void) strcat($$, $2->string);

		/* free up the right component */
		if ($2) { 
		    free($2->string);
		    free($2);
		}

		SPDEBUG(11) printf("--(words)--> (%s)\n", $$);
	    }
	|
	    {
		$$ = NULL;
	    }
	;

word	: STRING
	    {
	    	struct comp *pcomp;
		char *pc;

		$$ = (struct comp *) malloc(sizeof(struct comp));

		pc = $1;
		$$->string = strcpy((char *) malloc((unsigned) strlen($1) + 1), $1);
		$$->directive = 0;
	    }
	;

	
%%

#include "lex.yy.c"

/*ARGSUSED*/
yyerror(s)
    char *s;
{
     fprintf(stderr, 
	"error: syntax error at line %d in config file\n\t'%s' !\n", 
		++linenumber, currparsefile);
}

/*
 * void
 * tw_macro_parse(char *filename, FILE *fpin, FILE *fpout, 
 *						struct list **pp_entry_list)
 *
 *	wrapper around yyparse(), initiailzing input and output data.
 */

void
tw_macro_parse(filename, fpin, fpout, pp_entry_list)
    char *filename;
    FILE *fpin, *fpout;
    struct list **pp_entry_list;
{
    static int firsttime = 1;
    stackpointer = 0;

    /* set up input and output pointers */
    yyin = fpin;
    yyout = fpout;

#ifdef FLEX_SCANNER
    if (!firsttime) { 
	yyrestart(yyin);
    } else {
	firsttime = 0;
    }
#endif

    /* set up initial filename */
    strcpy( currparsefile, filename );

    pp_entry_list_global = pp_entry_list;

    (void) yyparse();
}

/* counters odd behaviour of flex -- Simon Leinen */
#ifdef yywrap
# undef yywrap
#endif

yywrap()
{
    /* check to see if we've reached the bottom of the @@include stack */
    if (include_pop()) {
	linenumber++;
	return 0;
    }

    /* close up parser */
    return 1;
}

/*
 * static char *
 * string_dequote(char *s)
 *
 *	remove pairs of quoted strings.
 */

static char *
string_dequote(s)
    char *s;
{
    char temp[1024];

    /* do we need to do anything? */
    if (s[0] != '"') 		{ return s; }

    (void) strncpy(temp, s+1, strlen(s) - 2);
    (void) strcpy(s, temp);

    return s;

}

/* 
 * void
 * include_push(char *filename, FILE **p_fp_old)
 *
 *	return a stdio (FILE *) pointer to the opened (filename), saving 
 *	the old (FILE *) pointer and line number on the stack.
 *
 *	returns (NULL) when we pop back to the original file.
 */

static void
include_push(filename, p_fp_old)
    char *filename;
    FILE **p_fp_old;
{
    static FILE *fp;
    char *pc;
    extern int  errno;

    /* check for stack overflow */
    if (stackpointer == INCLUDE_STACK_SZ) {
	fprintf(stderr,
	"error: too many nested includes at line %d in file\n\t'%s' !\n",
		linenumber, currparsefile);
	exit(1);
    }

    /* dequote the include filename */
    string_dequote(filename);

    /* save the old file pointer, filename, and linenumber on the stack */
    fp_stack[stackpointer] = *p_fp_old;

    (void) strcpy((pc = (char *) malloc((unsigned) strlen(currparsefile) + 1)), 
					currparsefile);
    filename_stack[stackpointer] = pc;

    linenumber_stack[stackpointer++] = linenumber;

    /* try opening the file */
    if ((fp = fopen(filename, "r")) == NULL) {
	if (errno == ENOENT) {
	    fprintf(stderr,
"error: @@include '%s': file not found at line %d in config file\n\t'%s' !\n",
		    filename, linenumber, currparsefile);
	    exit(1);
	}
	else {
	    char msg[100];
	    sprintf(msg, "%s: fopen()", filename);
	    perror(msg);
	    exit(1);
	}
    }

    /* replace old pointer with new */
    *p_fp_old = fp;

    /* reset line number and filename */
    linenumber = 0;
    strcpy( currparsefile, filename );
}

/*
 * FILE *
 * include_pop()
 *
 *	pop the last file structure off the @@include stack.
 *
 *	returns NULL when we've exhausted the stack.
 */

static FILE *
include_pop()
{
    /* check for stack underflow */
    if (stackpointer-- == 0)
	return NULL;
    (void) fclose(yyin);

    /* pop off the line numbers and the stdio file pointer */
    yyin = fp_stack[stackpointer];

#ifdef FLEX_SCANNER
    yyrestart(yyin);
#endif

    linenumber = linenumber_stack[stackpointer];
    strcpy( currparsefile, filename_stack[stackpointer] );
    free(filename_stack[stackpointer]);

    return yyin;
}

int
check_varname(pc)
    char *pc;
{
    for (; *pc; pc++) {
	if (!(isalnum(*pc) || (*pc == '_'))) {
	    fprintf(stderr,
"warning: illegal character '%c' in @@define at line %d in file\n\t'%s' !\n",
		*pc, linenumber, currparsefile);
	}
    }
    return 0;
}

