%{
/*
 * yacc_config.y 1.52 2001/06/22 04:17:17
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
    
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ds.h>
    
#include "cardmgr.h"

/* If bison: generate nicer error messages */ 
#define YYERROR_VERBOSE 1
 
/* from lex_config, for nice error messages */
extern char *current_file;
extern int current_lineno;

void yyerror(char *msg, ...);

static int add_binding(card_info_t *card, char *name, int fn);
static int add_module(device_info_t *card, char *name);

%}

%token DEVICE CARD ANONYMOUS TUPLE MANFID VERSION FUNCTION PCI
%token BIND CIS TO NEEDS_MTD MODULE OPTS CLASS
%token REGION JEDEC DTYPE DEFAULT MTD
%token INCLUDE EXCLUDE RESERVE IRQ_NO PORT MEMORY
%token STRING NUMBER

%union {
    char *str;
    u_long num;
    struct device_info_t *device;
    struct card_info_t *card;
    struct mtd_ident_t *mtd;
    struct adjust_list_t *adjust;
}

%type <str> STRING
%type <num> NUMBER
%type <adjust> adjust resource
%type <device> device needs_mtd module class
%type <card> card anonymous tuple manfid pci version function bind cis
%type <mtd> region jedec dtype default mtd
%%

list:	  /* nothing */
	| list adjust
		{
		    adjust_list_t **tail = &root_adjust;
		    while (*tail != NULL) tail = &(*tail)->next;
		    *tail = $2;
		}
	| list device
		{
		    $2->next = root_device;
		    root_device = $2;
		}
	| list mtd
		{
		    if ($2->mtd_type == 0) {
			yyerror("no ID method for this card");
			YYERROR;
		    }
		    if ($2->module == NULL) {
			yyerror("no MTD module specified");
			YYERROR;
		    }
		    $2->next = root_mtd;
		    root_mtd = $2;
		}
	| list card
		{
		    if ($2->ident_type == 0) {
			yyerror("no ID method for this card");
			YYERROR;
		    }
		    if ($2->bindings == 0) {
			yyerror("no function bindings");
			YYERROR;
		    }
		    if ($2->ident_type == FUNC_IDENT) {
			$2->next = root_func;
			root_func = $2;
		    } else {
			$2->next = root_card;
			root_card = $2;
		    }
		}
	| list opts
	| list mtd_opts
	| list error
	;

adjust:   INCLUDE resource
		{
		    $2->adj.Action = ADD_MANAGED_RESOURCE;
		    $$ = $2;
		}
	| EXCLUDE resource
		{
		    $2->adj.Action = REMOVE_MANAGED_RESOURCE;
		    $$ = $2;
		}
	| RESERVE resource
		{
		    $2->adj.Action = ADD_MANAGED_RESOURCE;
		    $2->adj.Attributes |= RES_RESERVED;
		    $$ = $2;
		}
	| adjust ',' resource
		{
		    $3->adj.Action = $1->adj.Action;
		    $3->adj.Attributes = $1->adj.Attributes;
		    $3->next = $1;
		    $$ = $3;
		}
	;

resource: IRQ_NO NUMBER
		{
		    $$ = calloc(sizeof(adjust_list_t), 1);
		    $$->adj.Resource = RES_IRQ;
		    $$->adj.resource.irq.IRQ = $2;
		}
	| PORT NUMBER '-' NUMBER
		{
		    if (($4 < $2) || ($4 > 0xffff)) {
			yyerror("invalid port range");
			YYERROR;
		    }
		    $$ = calloc(sizeof(adjust_list_t), 1);
		    $$->adj.Resource = RES_IO_RANGE;
		    $$->adj.resource.io.BasePort = $2;
		    $$->adj.resource.io.NumPorts = $4 - $2 + 1;
		}
	| MEMORY NUMBER '-' NUMBER
		{
		    if ($4 < $2) {
			yyerror("invalid address range");
			YYERROR;
		    }
		    $$ = calloc(sizeof(adjust_list_t), 1);
		    $$->adj.Resource = RES_MEMORY_RANGE;
		    $$->adj.resource.memory.Base = $2;
		    $$->adj.resource.memory.Size = $4 - $2 + 1;
		}
	;

device:	  DEVICE STRING
		{
		    $$ = calloc(sizeof(device_info_t), 1);
		    $$->refs = 1;
		    strcpy($$->dev_info, $2);
		    free($2);
		}
	| needs_mtd
	| module
	| class
	;

card:	  CARD STRING
		{
		    $$ = calloc(sizeof(card_info_t), 1);
		    $$->refs = 1;
		    $$->name = $2;
		}
	| anonymous
	| tuple
	| manfid
	| pci
	| version
	| function
	| bind
	| cis
	;

anonymous: card ANONYMOUS
		{
		    if ($1->ident_type != 0) {
			yyerror("ID method already defined");
			YYERROR;
		    }
		    if (blank_card) {
			yyerror("Anonymous card already defined");
			YYERROR;
		    }
		    $1->ident_type = BLANK_IDENT;
		    blank_card = $1;
		}
	;

tuple:	  card TUPLE NUMBER ',' NUMBER ',' STRING
		{
		    if ($1->ident_type != 0) {
			yyerror("ID method already defined");
			YYERROR;
		    }
		    $1->ident_type = TUPLE_IDENT;
		    $1->id.tuple.code = $3;
		    $1->id.tuple.ofs = $5;
		    $1->id.tuple.info = $7;
		}
	;

manfid:	  card MANFID NUMBER ',' NUMBER
		{
		    if ($1->ident_type & EXCL_IDENT) {
			yyerror("ID method already defined");
			YYERROR;
		    }
		    $1->ident_type = MANFID_IDENT;
		    $1->manfid.manf = $3;
		    $1->manfid.card = $5;
		}

pci:	  card PCI NUMBER ',' NUMBER
		{
		    if ($1->ident_type != 0) {
			yyerror("ID method already defined");
			YYERROR;
		    }
		    $1->ident_type = PCI_IDENT;
		    $1->manfid.manf = $3;
		    $1->manfid.card = $5;
		}

version:  card VERSION STRING
		{
		    if ($1->ident_type & EXCL_IDENT) {
			yyerror("ID method already defined\n");
			YYERROR;
		    }
		    $1->ident_type = VERS_1_IDENT;
		    $1->id.vers.ns = 1;
		    $1->id.vers.pi[0] = $3;
		}
	| version ',' STRING
		{
		    if ($1->id.vers.ns == 4) {
			yyerror("too many version strings");
			YYERROR;
		    }
		    $1->id.vers.pi[$1->id.vers.ns] = $3;
		    $1->id.vers.ns++;
		}
	;

function: card FUNCTION NUMBER
		{
		    if ($1->ident_type != 0) {
			yyerror("ID method already defined\n");
			YYERROR;
		    }
		    $1->ident_type = FUNC_IDENT;
		    $1->id.func.funcid = $3;
		}
	;

cis:	  card CIS STRING
		{ $1->cis_file = strdup($3); }
	;

bind:	  card BIND STRING
		{
		    if (add_binding($1, $3, 0) != 0)
			YYERROR;
		}
	| card BIND STRING TO NUMBER
		{
		    if (add_binding($1, $3, $5) != 0)
			YYERROR;
		}
	| bind ',' STRING
		{
		    if (add_binding($1, $3, 0) != 0)
			YYERROR;
		}
	| bind ',' STRING TO NUMBER
		{
		    if (add_binding($1, $3, $5) != 0)
			YYERROR;
		}
	;

needs_mtd: device NEEDS_MTD
		{
		    $1->needs_mtd = 1;
		}
	;

opts:	  MODULE STRING OPTS STRING
		{
		    device_info_t *d;
		    int i, found = 0;
		    for (d = root_device; d; d = d->next) {
			for (i = 0; i < d->modules; i++)
			    if (strcmp($2, d->module[i]) == 0) break;
			if (i < d->modules) {
			    if (d->opts[i])
				free(d->opts[i]);
			    d->opts[i] = strdup($4);
			    found = 1;
			}
		    }
		    free($2); free($4);
		    if (!found) {
			yyerror("module name not found!");
			YYERROR;
		    }
		}
	;

module:	  device MODULE STRING
		{
		    if (add_module($1, $3) != 0)
			YYERROR;
		}
	| module OPTS STRING
		{
		    if ($1->opts[$1->modules-1] == NULL) {
			$1->opts[$1->modules-1] = $3;
		    } else {
			yyerror("too many options");
			YYERROR;
		    }
		}
	| module ',' STRING
		{
		    if (add_module($1, $3) != 0)
			YYERROR;
		}
	;

class:	  device CLASS STRING
		{
		    if ($1->class != NULL) {
			yyerror("extra class string");
			YYERROR;
		    }
		    $1->class = $3;
		}
	;

region:	  REGION STRING
		{
		    $$ = calloc(sizeof(mtd_ident_t), 1);
		    $$->refs = 1;
		    $$->name = $2;
		}
	| dtype
	| jedec
	| default
	;

dtype:	  region DTYPE NUMBER
		{
		    if ($1->mtd_type != 0) {
			yyerror("ID method already defined");
			YYERROR;
		    }
		    $1->mtd_type = DTYPE_MTD;
		    $1->dtype = $3;
		}
	;

jedec:	  region JEDEC NUMBER NUMBER
		{
		    if ($1->mtd_type != 0) {
			yyerror("ID method already defined");
			YYERROR;
		    }
		    $1->mtd_type = JEDEC_MTD;
		    $1->jedec_mfr = $3;
		    $1->jedec_info = $4;
		}
	;

default:  region DEFAULT
		{
		    if ($1->mtd_type != 0) {
			yyerror("ID method already defined");
			YYERROR;
		    }
		    if (default_mtd) {
			yyerror("Default MTD already defined");
			YYERROR;
		    }
		    $1->mtd_type = DEFAULT_MTD;
		    default_mtd = $1;
		}
	;

mtd:	  region MTD STRING
		{
		    if ($1->module != NULL) {
			yyerror("extra MTD entry");
			YYERROR;
		    }
		    $1->module = $3;
		}
	| mtd OPTS STRING
		{
		    if ($1->opts == NULL) {
			$1->opts = $3;
		    } else {
			yyerror("too many options");
			YYERROR;
		    }
		}
	;

mtd_opts:  MTD STRING OPTS STRING
		{
		    mtd_ident_t *m;
		    int found = 0;
		    for (m = root_mtd; m; m = m->next)
			if (strcmp($2, m->module) == 0) break;
		    if (m) {
			if (m->opts) free(m->opts);
			m->opts = strdup($4);
			found = 1;
		    }
		    free($2); free($4);
		    if (!found) {
			yyerror("MTD name not found!");
			YYERROR;
		    }
		}
	;

%%
void yyerror(char *msg, ...)
{
     va_list ap;
     char str[256];

     va_start(ap, msg);
     sprintf(str, "config error, file '%s' line %d: ",
	     current_file, current_lineno);
     vsprintf(str+strlen(str), msg, ap);
#if YYDEBUG
     fprintf(stderr, "%s\n", str);
#else
     syslog(LOG_ERR, "%s", str);
#endif
     va_end(ap);
}

static int add_binding(card_info_t *card, char *name, int fn)
{
    device_info_t *dev = root_device;
    if (card->bindings == MAX_BINDINGS) {
	yyerror("too many bindings\n");
	return -1;
    }
    for (; dev; dev = dev->next)
	if (strcmp((char *)dev->dev_info, name) == 0) break;
    if (dev == NULL) {
	yyerror("unknown device: %s", name);
	return -1;
    }
    card->device[card->bindings] = dev;
    card->dev_fn[card->bindings] = fn;
    card->bindings++;
    free(name);
    return 0;
}

static int add_module(device_info_t *dev, char *name)
{
    if (dev->modules == MAX_MODULES) {
	yyerror("too many modules");
	return -1;
    }
    dev->module[dev->modules] = name;
    dev->opts[dev->modules] = NULL;
    dev->modules++;
    return 0;
}

#if YYDEBUG
adjust_list_t *root_adjust = NULL;
device_info_t *root_device = NULL;
card_info_t *root_card = NULL, *blank_card = NULL, *root_func = NULL;
mtd_ident_t *root_mtd = NULL, *default_mtd = NULL;

void main(int argc, char *argv[])
{
    yydebug = 1;
    if (argc > 1)
	parse_configfile(argv[1]);
}
#endif
