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
 * a60-parse.y:						aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * The main part of the Algol 60 parser module.
 *
 * The grammer contains one reduce/reduce conflict (got by the
 * error recovery).
 *
 * The unary '-' usage is still wrong. It's possible to write (and use)
 * 	a := 33 + - 7;
 * but that's not allowed in RRA60.
 *
 * The scanner should resolove real values like 1.44 '10' +7. But this
 * is still done by the parser. Not wrong, but not fine.
 */

%{
#include "comm.h"
#include "a60.h"
#include "util.h"
#include "tree.h"
#include "run.h"
#include "bltin.h"


/* number of errors found. */
int nerrors = 0;

/* flag for unary minus parsed. */
int unary_minus = 0;

/* force code for parser debugging to be included: */
#ifdef PARSEDEBUG
#define YYDEBUG	1
#endif

/*** in future: #ifdef YYBISON ***/
#ifndef YYBYACC

#ifdef ALLOCA_MISSING
/*
 * if no alloca() call is avail, provide yyoverflow to catch bison
 * stack-expanding.
 * its somewhat confusing: yyoverflow is expected to be defined, but
 * used with ifdef'd parameters, so it has to be a function.
 * [see below the grammer for a60_yyoverflow ()]
 */

/* to be defined: */
#define yyoverflow 	a60_yyoverflow
/* forward: */
static void a60_yyoverflow ();
#endif /* ALLOCA_MISSING */
#endif /* ! YYBISON */

%}

%start a60program

/*
 * owntype is a flat-used structure. not nice but it was to fizzly to
 * allocate and free space for em.
 */

%union {
	long itype;
	double rtype;
	char *str;
	TREE *tree;
	SYMTAB *sym;
	EXPR *expr;
	BOUND *bound;
	LHELM *lhelm;
	MINDEX *mindex;
	FORELM *forelm;
	FORSTMT *forstmt;
	OWNTYPE otype;
	ENUM type_tag typ;
}

/* never expected: TCOMMENT. */
%token	TCOMMENT

/* keywords: */
%token TTEN
%token TBEGIN TEND
%token TGOTO TFOR TDO TWHILE TSTEP TUNTIL TIF TTHEN TELSE TSWITCH
%token TPROC TVALUE TCODE
%token TTRUE TFALSE
%token TINTEGER TREAL TBOOL TLABEL TOWN TARRAY TSTRING
%token TPOW TDIV TASSIGN

%token TLESS TNOTGREATER TEQUAL TNOTLESS TGREATER TNOTEQUAL
%token TAND TOR TNOT TIMPL TEQUIV

%token <itype> INUM
%token <rtype> RNUM
%token <str>   NAME STRING

%type <str> identifier label

%type <itype> logical_val signed_inum
%type <rtype> real_value

%type <tree>  program block unlab_block
%type <tree>  unlab_basic_stmt comp_stmt unlab_comp comp_tail
%type <tree>  dummy_stmt basic_stmt uncond_stmt
%type <tree>  stmt cond_stmt for_stmt goto_stmt assign_stmt
%type <tree>  if_stmt tlabel proc_stmt pd_proc_body

%type <sym>   decl type_decl array_decl switch_decl proc_decl type_list 
%type <sym>   array_seg array_list
%type <sym>   pd_proc_head pd_proc_hhead pd_form_parmpart
%type <sym>   pd_form_parmlist pd_form_parm
%type <sym>   pd_val_part pd_spec_part pd_spec_idlist pd_ident_list

%type <typ>   type pd_spec pd_proc_type
%type <otype> loc_or_own

%type <expr>  string arith_expr simple_expr mix_expr mix_prim
%type <expr>  subscr_expr relation bool_expr func_desig right_part
%type <expr>  design_expr simp_dexpr switch_des switch_list
%type <expr>  if_clause act_parmpart act_parmlist act_parm

%type <bound> bound_pair bound_pair_list
%type <lhelm> variable left_part left_part_list
%type <mindex> subscr_list

%type <forelm>  for_lelm for_list
%type <forstmt> for_clause

%right	TASSIGN
%left	TEQUIV
%left	TIMPL
%left	TOR
%left	TAND
%left	TLESS TNOTGREATER TEQUAL TNOTLESS TGREATER TNOTEQUAL
%left	'+' '-'
%left	'*' '/' TDIV
%left	TPOW
%left	UNARY

%%

a60program:
	/* empty */
	  {
		  rtree = 0;
		  yyerror ("no vaild input found");
	  }
	|
	  {
		  open_new_scope ();
		  init_bltin ();
	  }
	  program
	  {
		  TREE *new = new_tree (t_block);
		  new->runme = run_block;
		  if (! current_scope)
			  xabort ("cannot recover from this error");
		  new->u.block = current_scope->block;
		  new->u.block->symtab = *current_scope->symtab;
		  new->u.block->nact = 
			  set_actidx (*current_scope->symtab);
		  new->u.block->stmt = $2;
		  new->next = 0;
		  rtree = new;
	  }
	;


/* Logical values : */

logical_val
	: TTRUE
		{ $$ = 1; }
	| TFALSE
		{ $$ = 0; }
	;


/* Identifiers : */

identifier
	: NAME
		{ $$ = cleanup_identifier ($1); }
	;


/* Strings */

string
	: STRING
	  {
		  EXPR *new = new_expr (e_string, ty_string);
		  new->u.string = $1;
		  $$ = new;
	  }
	;


/* Variables : */

variable
	: identifier
	  {
		  LHELM *new = make_var_ref ($1, 1);
		  $$ = new;
	  }
	| identifier '[' subscr_list ']'
	  {
		  LHELM *new = make_var_ref ($1, 1);
		  if (new)
			  new->mindex = $3;
		  $$ = new;
	  }
	;

subscr_list
	: subscr_expr
	  {
		  MINDEX *new = new_mindex ($1);
		  $$ = new;
	  }
	| subscr_list ',' subscr_expr
	  {
		  MINDEX *new = new_mindex ($3);
		  MINDEX **i;
		  for (i = &($1); *i; i = &(*i)->next);
		  *i = new;
		  $$ = $1;
	  }
	;

subscr_expr
	: arith_expr
		{ $$ = $1; }
	;


/* function designators : */

/*
 * functions without arguments are recognized as variables.
 */

func_desig
	: identifier '(' act_parmlist ')'
	  {
		  EXPR *expr = new_expr (e_fcall, ty_unknown);
		  LHELM *new = make_var_ref ($1, 0);
		  if (new) {
			  new->u.fcall = new_funcall (new->sym, $3);
			  expr->u.lhelm = new;
		  }
		  $$ = expr;
	  }
	;

/* arithmetik expressions : */

arith_expr
	: simple_expr
		{ $$ = $1; }
	| if_clause simple_expr TELSE arith_expr
	  {
		  EXPR *new = new_expr (e_condexpr, ty_unknown);
		  new->u.expr[0] = $1;
		  new->u.expr[1] = $2;
		  new->u.expr[2] = $4;
		  $$ = new;
	  }
	;

simple_expr
	: '+' mix_expr %prec UNARY
		{ $$ = $2; }
	| mix_expr
		{ $$ = $1; }
	;

mix_expr
	: mix_expr '*' mix_expr
		{ $$ = new_xmix_expr ($1, e_op_times, $3); }
	| mix_expr '/' mix_expr
		{ $$ = new_xmix_expr ($1, e_op_rdiv, $3); }
	| mix_expr '+' mix_expr
		{ $$ = new_xmix_expr ($1, e_op_plus, $3); }
	| mix_expr '-' mix_expr
		{ $$ = new_xmix_expr ($1, e_op_minus, $3); }
	| mix_expr TPOW mix_expr
		{ $$ = new_xmix_expr ($1, e_op_pow, $3); }
	| mix_expr TDIV mix_expr
		{ $$ = new_xmix_expr ($1, e_op_idiv, $3); }
	| mix_expr TEQUIV mix_expr
		{ $$ = new_xmix_expr ($1, e_op_equiv, $3); }
	| mix_expr TIMPL mix_expr
		{ $$ = new_xmix_expr ($1, e_op_impl, $3); }
	| mix_expr TOR mix_expr
		{ $$ = new_xmix_expr ($1, e_op_or, $3); }
	| mix_expr TAND mix_expr
		{ $$ = new_xmix_expr ($1, e_op_and, $3); }
	| TNOT mix_expr %prec UNARY
		{ $$ = new_xmix_expr ($2, e_op_not, (EXPR *) 0); }
	| relation
	  {
		  if (unary_minus)
			  unary_minus = 0,
			  yyerror ("unary `-' invalid in relation");
		  $$ = $1;
	  }
	| mix_prim
	  {
		  if (unary_minus) {
			  unary_minus = 0;
			  $$ = new_mix_expr ($1, e_op_neg, (EXPR *) 0);
		  }
		  else
			  $$ = $1;
	  }
	| '-' mix_prim %prec UNARY
	  {
		  $$ = new_mix_expr ($2, e_op_neg, (EXPR *) 0);
	  }
	;

relation
	: mix_expr TLESS mix_expr
		{ $$ = new_xmix_expr ($1, e_op_less, $3); }
	| mix_expr TNOTGREATER mix_expr
		{ $$ = new_xmix_expr ($1, e_op_notgreater, $3); }
	| mix_expr TEQUAL mix_expr
		{ $$ = new_xmix_expr ($1, e_op_equal, $3); }
	| mix_expr TNOTLESS mix_expr
		{ $$ = new_xmix_expr ($1, e_op_notless, $3); }
	| mix_expr TGREATER mix_expr
		{ $$ = new_xmix_expr ($1, e_op_greater, $3); }
	| mix_expr TNOTEQUAL mix_expr
		{ $$ = new_xmix_expr ($1, e_op_notequal, $3); }
	;

mix_prim
	: INUM
	  {
		  EXPR *new = new_expr (e_ival, ty_integer);
		  new->u.ival = $1;
		  $$ = new;
	  }
	| real_value
	  {
		  EXPR *new = new_expr (e_rval, ty_real);
		  new->u.rval = $1;
		  $$ = new;
	  }
	| func_desig
	  {
		  $$ = $1;
	  }
	| variable
	  {
		  EXPR *new;

		  if (! $1) {
			  new = (EXPR *) 0;
		  }
		  else {
			  new = new_expr (e_symbol, ty_unknown);
			  new->u.lhelm = $1;
			  
			  if (TIS_PROC($1->sym->type)) {
				  LHELM *lhelm = $1;
				  new->tag = e_fcall;
				  lhelm->u.fcall = new_funcall (lhelm->sym,
								(EXPR *) 0);
				  new->u.lhelm = lhelm;
			  }
		  }

		  $$ = new;
	  }
	| logical_val
	  {
		  EXPR *new = new_expr (e_bool, ty_bool);
		  new->u.bool = $1;
		  $$ = new;
	  }
	| '(' simple_expr ')'
		{ $$ = $2; }
	;

bool_expr: arith_expr;


/* designational expr : */

design_expr
	: simp_dexpr { $$ = $1; }
	| if_clause simp_dexpr TELSE design_expr
	  {
		  EXPR *new = new_expr (e_condexpr, ty_unknown);
		  new->u.expr[0] = $1;
		  new->u.expr[1] = $2;
		  new->u.expr[2] = $4;
		  $$ = new;
	  }
	;

simp_dexpr
	: label
	  {
		  SYMTAB *new = new_symbol ($1, ty_label, s_undef);
		  EXPR *ex = new_expr (e_label, ty_label);
		  ex->u.label = new;
		  $$ = ex;
	  }
	| switch_des
		{ $$ = $1; }
	| '(' design_expr ')'
		{ $$ = $2; }
	;

switch_des
	: identifier '[' subscr_expr ']'
	  {
		  EXPR *ex = new_expr (e_switch, ty_switch);
		  ex->u.eswitch = new_eswitch ($1, $3);
		  $$ = ex;
	  }
	;


/* compound statements and blocks : */

program
	: block
		{ $$ = $1; }
	| comp_stmt
		{ $$ = $1; }
	;

block
	: unlab_block
		{ $$ = $1; }
	| tlabel block
	  {
		  TREE *p1 = $1, *p2 = $2;
		  p1->next = p2;
		  $$ = p1;
	  }
	;

comp_stmt
	: unlab_comp
		{ $$ = $1; }
	| tlabel comp_stmt
	  {
		  TREE *p1 = $1, *p2 = $2;
		  p1->next = p2;
		  $$ = p1;
	  }
	;

unlab_block
	: block_head ';' comp_tail
	  {
		  TREE *new = new_tree (t_block);
		  new->runme = run_block;
		  new->u.block = current_scope->block;
		  /* new->u.block->symtab = current_scope->symtab; */
		  new->u.block->nact = 
			  set_actidx (*current_scope->symtab);
		  new->u.block->stmt = $3;
		  new->next = 0;
		  $$ = new;
		  close_current_scope ();
	  }
	;

unlab_comp
	: TBEGIN
	  {
		  open_new_scope ();
	  }
	  comp_tail
	  {
		  TREE *p = $3;
		  TREE *new = new_tree (t_block);
		  new->runme = run_block;
		  new->u.block = current_scope->block;
		  new->u.block->stmt = p;
		  new->next = 0;
		  close_current_scope ();
		  $$ = new;
	  }
	;

block_head
	: TBEGIN
	  {
		  open_new_scope ();
	  }
	  decl
	  {
		  SYMTAB *p = $3;
		  examine_and_append_symtab (current_scope->symtab, p);
	  }
	| block_head ';' decl
	  {
		  SYMTAB *p = $3;
		  examine_and_append_symtab (current_scope->symtab, p);
	  }
	| error
		{ /** yyerror ("declaration error"); **/ }
	;

comp_tail
	: stmt TEND
		{ $$ = $1; }
	| stmt ';' comp_tail
	  {
		  if (! $1) {
			  /* there was an error parsing stmt */
			  $$ = $3;
		  }
		  else {
			  append_stmt (&($1)->next, $3, 0);
			  $$ = $1;
		  }
	  }
	;

stmt
	: uncond_stmt
		{ $$ = $1; }
	| cond_stmt
		{ $$ = $1; }
	| for_stmt
		{ $$ = $1; }
	;

uncond_stmt
	: basic_stmt
		{ $$ = $1; }
	| comp_stmt
		{ $$ = $1; }
	| block
		{ $$ = $1; }
	;

basic_stmt
	: unlab_basic_stmt
		{ $$ = $1; }
	| tlabel basic_stmt
	  {
		  ($1)->next = $2;
		  $$ = $1;

	  }
	;

unlab_basic_stmt
	: assign_stmt
		{ $$ = $1; }
	| goto_stmt
		{ $$ = $1; }
	| dummy_stmt
		{ $$ = $1; }
	| proc_stmt
		{ $$ = $1; }
	| error
		{ $$ = 0; }
	;


/* assignment statements : */

assign_stmt
	: left_part_list right_part
		{ $$ = new_assign_stmt ($1, $2); }
	;

right_part
	: arith_expr
		{ $$ = $1; }
	;

left_part_list
	: left_part
		{ $$ = $1; }
	| left_part_list left_part
	  {
		  LHELM **l = &($1);
		  for (; *l; l = &(*l)->next)
			  continue;
		  *l = $2;
		  $$ = $1;
	  }
	;

left_part
	: variable TASSIGN
		{ $$ = $1; }
	;


/* goto statements : */

goto_stmt
	: TGOTO design_expr
		{ $$ = new_goto_stmt ($2); }
	;


/* dummy statements : */

dummy_stmt
	: /* empty */
		{ $$ = new_tree (t_dummy_stmt); }
	;


/* conditional statements : */

cond_stmt
	: if_stmt
		{ $$ = $1; }
	| if_stmt TELSE stmt
	  {
		  ($1)->u.ifstmt->telse = $3;
		  $$ = $1;
	  }
	| if_clause for_stmt
	  {
		  TREE *new = new_if_stmt ($1);
		  new->u.ifstmt->tthen = $2;
		  $$ = new;
	  }
	| tlabel cond_stmt
	  {
		  ($1)->next = $2;
		  $$ = $1;
	  }
	;

if_stmt
	: if_clause uncond_stmt
	  {
		  TREE *new = new_if_stmt ($1);
		  new->u.ifstmt->tthen = $2;
		  $$ = new;
	  }
	;

if_clause
	: TIF bool_expr TTHEN
		{ $$ = $2; }
	;


/* for statements : */

for_stmt
	: for_clause stmt
	  {
		  TREE *new = new_tree (t_for_stmt);
		  new->runme = run_forstmt;
		  new->u.forstmt = $1;
		  new->u.forstmt->stmt = $2;
		  $$ = new;
	  }
	| tlabel for_stmt
	  {
		  ($1)->next = $2;
		  $$ = $2;
	  }
	;

for_clause
	: TFOR variable TASSIGN for_list TDO
	  {
		  FORSTMT *new = TALLOC (FORSTMT);
		  new->lvar = $2;
		  new->forelm = $4;
		  $$ = new;
	  }
	;

for_list
	: for_lelm
		{ $$ = $1; }
	| for_list ',' for_lelm
	  {
		  FORELM **fe = &($1);
		  while (*fe)
			  fe = & (*fe)->next;
		  *fe = $3;
		  $$ = $1;
	  }
	;

for_lelm
	: arith_expr
	  {
		  FORELM *new = TALLOC (FORELM);
		  new->tag = fe_expr;
		  new->expr[0] = $1;
		  new->next = (FORELM *) 0;
		  $$ = new;
	  }
	| arith_expr TSTEP arith_expr TUNTIL arith_expr
	  {
		  FORELM *new = TALLOC (FORELM);
		  new->tag = fe_until;
		  new->expr[0] = $1;
		  new->expr[1] = $3;
		  new->expr[2] = $5;
		  new->next = (FORELM *) 0;
		  $$ = new;
	  }
	| arith_expr TWHILE bool_expr
	  {
		  FORELM *new = TALLOC (FORELM);
		  new->tag = fe_while;
		  new->expr[0] = $1;
		  new->expr[1] = $3;
		  new->next = (FORELM *) 0;
		  $$ = new;
	  }
	;


/* Procedure statements : */

proc_stmt
	: identifier act_parmpart
	  {
		  TREE *new = new_tree (t_proc_stmt);
		  SYMTAB *sym = new_symbol ($1, ty_proc, s_undef);
		  new->runme = run_proc;
		  new->u.funcall = new_funcall (sym, $2);
		  $$ = new;
	  }
	;

act_parmpart
	: /* empty */
		{ $$ = (EXPR *) 0; }
	| '(' act_parmlist ')'
		{ $$ = $2; }
	;

act_parmlist
	: act_parm
		{ $$ = $1; }
	| act_parmlist parm_delim act_parm
	  {
		  EXPR **expr = &($1);
		  while (*expr)
			  expr = &(*expr)->next;
		  *expr = $3;
		  $$ = $1;
	  }
	;

parm_delim
	: ','
		{ /* do nothing */ }
	| ')' letter_string ':' '('
		{ /* do nothing */ }
	;

letter_string
	: NAME
		{ /* do nothing */ }
	;

act_parm
	: string
		{ $$ = $1; }
	| arith_expr
		{ $$ = $1; }
	;


/* Declarations : */

decl
	: type_decl
		{ $$ = $1; }
	| array_decl
		{ $$ = $1; }
	| switch_decl
		{ $$ = $1; }
	| proc_decl
		{ $$ = $1; }
	;

/* Type declarations : */

type_decl
	: loc_or_own type_list
	  {
		  ENUM type_tag p1 = ($1).type;
		  int own = ($1).own;
		  SYMTAB *p2 = $2;
		  sym_all_type (p2, p1, own);
		  $$ = p2;
	  }
	;

loc_or_own
	: type
	  {
		  OWNTYPE new;
		  new.type = $1;
		  new.own = 0;
		  $$ = new;
	  }
	| TOWN type
	  {
		  OWNTYPE new;
		  new.type = $2;
		  new.own = 1;
		  $$ = new;
	  }
	;

type_list
	: identifier
	  {
		  SYMTAB *new = new_symbol ($1, ty_unknown, s_defined);
		  new->block = current_scope->block;
		  $$ = new;
	  }
	| type_list ',' identifier 
	  {
		  if (find_in_symtab ($1, $3)) {
			  yyerror ("duplicate symbol");
			  $$ = $1;
		  }
		  else {
			  SYMTAB *new = new_symbol ($3, ty_unknown, s_defined);
			  new->next = $1;
			  new->block = current_scope->block;
			  $$ = new;
		  }
	  }
	;

type
	: TINTEGER
		{ $$ = ty_integer; }
	| TREAL
		{ $$ = ty_real; }
	| TBOOL
		{ $$ = ty_bool; }
	;


/* Array declarations : */

array_decl
	: TARRAY array_list
	  {
		  sym_all_type ($2, TAR_TYPE(ty_real), 0);
		  $$ = $2;
	  }
	| loc_or_own TARRAY array_list
	  {
		  sym_all_type ($3, TAR_TYPE(($1).type), ($1).own);
		  $$ = $3;
	  }
	;

array_list
	: array_seg
		{ $$ = $1; }
	| array_list ',' array_seg
	  {
		  examine_and_append_symtab (&($1), $3);
		  $$ = $1;
	  }
	;

array_seg
	: identifier '[' bound_pair_list ']'
	  {
		  SYMTAB *new = new_symbol ($1, ty_unknown, s_defined);
		  new->block = current_scope->block;
		  new->u.arr = TALLOC (ARRAY);
		  new->u.arr->bound = $3;
		  new->u.arr->dim = num_bounds ($3);
		  /** new->u.arr->val = 0; **/
		  $$ = new;
	  }
	| identifier ',' array_seg
	  {
		  SYMTAB *new = new_symbol ($1, ty_unknown, s_defined);
		  new->block = current_scope->block;
		  new->u.arr = TALLOC (ARRAY);
		  new->u.arr->bound = ($3)->u.arr->bound;
		  new->u.arr->dim = ($3)->u.arr->dim;
		  /** new->u.arr->val = 0; **/
		  new->next = $3;
		  $$ = new;
		  
	  }
	;

bound_pair_list
	: bound_pair
		  { $$ = $1; }
	| bound_pair_list ',' bound_pair
	  {
		  BOUND **b = &($1);
		  while (*b)
			  b = &(*b)->next;
		  *b = $3;
		  $$ = $1;
	  }
	;

bound_pair
	: arith_expr ':' arith_expr
	  {
		  BOUND *new = TALLOC (BOUND);
		  new->low = $1;
		  new->high = $3;
		  $$ = new;
	  }
	;


/* Switch declarations : */

switch_decl
	: TSWITCH identifier TASSIGN switch_list
	  {
		  SYMTAB *new = new_symbol ($2, ty_switch, s_defined);
		  new->block = current_scope->block;
		  new->u.dexpr = $4;
		  $$ = new;
	  }
	;

switch_list
	: design_expr
		{ $$ = $1; }
	| switch_list ',' design_expr
	  {
		  append_expr (&($1), $3);
		  $$ = $1;
	  }
	;


/* Procedure declarations : */

proc_decl
	: pd_proc_head pd_proc_body
	  {
		  ($1)->u.pproc->block->stmt = $2;
		  close_current_scope ();
		  $$ = 0;
	  }
	;

pd_proc_type
	: /* empty */
		{ $$ = ty_proc; }
	| type
		{ $$ = TPROC_TYPE($1); }
	;

pd_proc_body
	: stmt
		{ $$ = $1; }
	| TCODE
		{ $$ = (TREE *) 0; }
	;


pd_proc_hhead
	: pd_proc_type TPROC identifier
	  {
		  SYMTAB *psym = new_symbol ($3, $1, s_defined);
		  PPROC *new = TALLOC (PPROC);
		  examine_and_append_symtab (current_scope->symtab, psym);
		  psym->block = current_scope->block;
		  psym->u.pproc = new;
		  open_new_scope ();
		  new->block = current_scope->block;
		  $$ = psym;
	  }
	;

pd_proc_head
	: pd_proc_hhead pd_form_parmpart ';' pd_val_part pd_spec_part
	  {
		  SYMTAB *psym = $1;
		  examine_and_append_symtab (current_scope->symtab, $2);
		  psym->u.pproc->nparm = num_symbols ($2);
		  psym->u.pproc->block->nact = 
			  set_actidx (*current_scope->symtab);
		  replace_type (*current_scope->symtab, $5);
		  set_by_value (*current_scope->symtab, $4);
		  $$ = psym;
	  }
	;

pd_spec_part
	: /* empty */
		{ $$ = (SYMTAB *) 0; }
	| pd_spec_idlist
		{ $$ = $1; }
	;

pd_spec_idlist
	: pd_spec pd_ident_list ';'
	  {
		  sym_all_type ($2, $1, 0);
		  $$ = $2;
	  }
	| pd_spec_idlist pd_spec pd_ident_list ';'
	  {
		  sym_all_type ($3, $2, 0);
		  examine_and_append_symtab (&($1), $3);
		  $$ = $1;
	  }
	;

pd_spec
	: TSTRING
		{ $$ = ty_string; }
	| type
		{ $$ = $1; }
	| TARRAY
		{ $$ = ty_real_array; }
	| type TARRAY
		{ $$ = TAR_TYPE($1); }
	| TLABEL
		{ $$ = ty_label; }
	| TSWITCH
		{ $$ = ty_switch; }
	| TPROC
		{ $$ = ty_proc; }
	| type TPROC
		{ $$ = TPROC_TYPE($1); }
	;

pd_val_part
	: /* empty */
		{ $$ = (SYMTAB *) 0; }
	| TVALUE pd_ident_list ';'
		{ $$ = $2; }
	;

pd_ident_list
	: identifier
	  {
		  $$ = new_symbol ($1, ty_unknown, s_byname);
	  }
	| pd_ident_list ',' identifier
	  {
		  SYMTAB *new = new_symbol ($3, ty_unknown, s_byname);
		  examine_and_append_symtab (&(($1)->next), new);
		  $$ = $1;
	  }
	;

pd_form_parmpart
	: /* empty */
		{ $$ = (SYMTAB *) 0; }
	| '(' pd_form_parmlist ')'
		{ $$ = $2; }
	;

pd_form_parmlist
	: pd_form_parm
		{ $$ = $1; }
	| pd_form_parmlist parm_delim pd_form_parm
	  {
		  examine_and_append_symtab (&($1), $3);
		  $$ = $1;
	  }
	;
	
pd_form_parm
	: identifier
	  {
		  SYMTAB *new = new_symbol ($1, ty_unknown, s_byname);
		  new->block = current_scope->block;
		  $$ = new;
	  }
	;


/* Label parsing: */

tlabel
	: label ':'
	  {
		  TREE *new = new_tree (t_label);
		  SYMTAB *s = new_symbol ($1, ty_label, s_defined);
		  s->block = current_scope->block;
		  new->u.symbol = s;
		  examine_and_append_symtab (current_scope->symtab, s);
		  $$ = new;
	  }
	;

label
	: identifier
		{ $$ = $1; }
	| INUM
	  {
		  char tmp[32];

		  sprintf(tmp, "%ld", $1);
		  $$ = xstrdup (tmp);
	  }
	;

/* real value: */

signed_inum
	: INUM
		{ $$ = $1; }
	| '+' INUM
		{ $$ = $2; }
	| '-' INUM
		{ $$ = - ($2); }
	;

real_value
	: RNUM
		{ $$ = $1; }
	| RNUM TTEN signed_inum
		{ $$ = ($1) * pow ((double) 10, (double) ($3)); }
	| INUM TTEN signed_inum
		{ $$ = (double) ($1) * pow ((double) 10, (double) ($3)); }
	| TTEN signed_inum
		{ $$ = pow ((double) 10, (double) ($2)); }
	;

%%

/*** in future: #ifdef YYBISON ***/
#ifndef YYBYACC
/*
 * the yyoverflow function for use with bison to avoid use of alloca():
 */
#ifdef ALLOCA_MISSING
#ifdef YYLSP_NEEDED
static void
a60_yyoverflow (s, yyss1, size_yyss, yyvs1, size_yyvs, yyls1, size_yyls, yysp)
char *s;
short *yyss1;
int size_yyss;
YYSTYPE *yyvs1;
int size_yyvs;
YYLTYPE *yyls1;
int size_yyls;
int *yysp;
{
 	yyerror (s);
}
#else /* ! YYLSP_NEEDED */
static void
a60_yyoverflow (s, yyss1, size_yyss, yyvs1, size_yyvs, yysp)
char *s;
short *yyss1;
int size_yyss;
YYSTYPE *yyvs1;
int size_yyvs;
int *yysp;
{
 	yyerror (s);
}
#endif /* ! YYLSP_NEEDED */
#endif /* ALLOCA_MISSING */
#endif /* ! YYBISON */

/* end of a60-parse.y */
