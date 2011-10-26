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
 * symtab.c:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#include "comm.h"
#include "util.h"
#include "a60.h"
#include "run.h"
#include "tree.h"


char *sym_tag_name[] = {
	"defined",
	"undef'd",
	"by-name",
	"by-value",
	"last_sym_tag_name"
};


SYMTAB *
new_symbol (name, type, tag)
char *name;
ENUM type_tag type;
ENUM sym_tag tag;
{
	SYMTAB *new = TALLOC (SYMTAB);
	
	new->name = name;
	new->type = type;
	new->tag = tag;
	new->own = 0;
	new->actidx = -1;
	new->next = 0;

	new->source = infname;
	new->lineno = lineno;

	return new;
}


/*
 * return a new data record; next-ptr (last activation) is appended
 * from the parameter.
 */

DATA *
new_data ()
{
	DATA *new = TALLOC (DATA);

	return new;
}



void
sym_all_type (s, type, own)
SYMTAB *s;
ENUM type_tag type;
int own;
{
	while (s) {
		s->type = type;
		s->own = own;
		s = s->next;
	}
}


SYMTAB *
find_in_symtab (symtab, name)
SYMTAB *symtab;
char *name;
{
	for ( ; symtab && strcmp (symtab->name, name);
	     symtab=symtab->next);
	
	return symtab;
}


void
append_symtab (s1, s2)
SYMTAB **s1, *s2;
{
	while (*s1)
		s1 = & (*s1)->next;

	*s1 = s2;
}


void
examine_and_append_symtab (s1, s2)
SYMTAB **s1, *s2;
{
	SYMTAB *s;

	if(! s2 || ! s1) {
		return;
	}

	for (s=s2; s; s=s->next) {

		if (find_in_symtab (*s1, s->name)) {
			a60_error (infname, lineno,
				   "duplicate symbol name `%s'\n", s->name);
			nerrors++;
		}
	}

	append_symtab (s1, s2);
}


/*
 *  remove spaces...
 */

char *
cleanup_identifier (str)
char *str;
{
	char *from_ptr = str, *to_ptr = str;

	while (*from_ptr) {
		if (*from_ptr != ' ') 
			*to_ptr++ = *from_ptr;
		from_ptr++;
	}

	*to_ptr = 0;

	return str;
}


static void
print_bounds (b)
BOUND *b;
{
	if (! b)
		return;

	printf ("[");
	print_expr (b->low);
	printf (":");
	print_expr (b->high);
	printf ("]");

	print_bounds (b->next);
}


static void
print_indent_proc (s, n)
SYMTAB *s;
int n;
{
	print_indent (n);

	if (s->type == ty_proc)
		printf ("(void) ");
	else
		printf ("(%s) ",
			type_tag_name[TPROC_BASE(s->type)]);
	printf("PROC [nparms: %d] pblock: (0x%lx; up 0x%lx; ext_ref %d)\n",
	       s->u.pproc->nparm, (long) s->u.pproc->block,
	       (long) s->u.pproc->block->up,
	       (int) s->u.pproc->block->ext_ref);


	print_indent_symtab (s->u.pproc->block->symtab, n+4);

	if(! s->u.pproc->block->stmt) {
		print_indent (n+4);
		printf ("<external reference>\n");
	}
	else
		print_indent_tree (s->u.pproc->block->stmt, 0, n+4);
}


static void
print_indent_switch_decl (s, n)
SYMTAB *s;
int n;
{
	EXPR *expr;

	for (expr = s->u.dexpr; expr; expr = expr->next) {
		if (expr != s->u.dexpr)
			print_indent (n);
		print_expr (expr);
		if (expr->next)
			printf (",\n");
		else
			printf (";\n");
	}
}


void
print_indent_symbol (s, n)
SYMTAB *s;
int n;
{
	if (! s)
		return;

	print_indent (n);
	printf ("%s %s (%s)",
		type_tag_name[s->type],
		s->name,
		sym_tag_name[s->tag]);
	
	if (TIS_ARR(s->type)) {
		if (! s->u.arr)
			a60_error ("INTERNAL", 0, "INTERNAL: arr in nil\n");
		else {
			printf (" dim %d; ", s->u.arr->dim);
			print_bounds (s->u.arr->bound);
		}
	}

	printf (" (sym 0x%lx;%s idx %d; block 0x%lx)\n",
		(long) s, (s->own) ? " OWN" : "",
		s->actidx, (long) s->block);

	if (s->tag != s_byname && TIS_PROC(s->type))
		print_indent_proc (s, n+2);

	if (s->tag != s_byname && s->type == ty_switch) {
		print_indent (n+4);
		printf (" := ");
		print_indent_switch_decl (s, n+8);
	}
}


void
print_indent_symtab (s, n)
SYMTAB *s;
int n;
{
	if (s) {
		print_indent_symbol (s, n);
		print_indent_symtab (s->next, n);
	}
}


/*
 * scope management; on parsetime the scope list is handled like
 * a stack; a new scope is instered at the beginning on a block
 * entry and removed on exit.
 */

SCOPE *current_scope = 0;
static SCOPE *sroot = 0;

void
open_new_scope ()
{
	SCOPE *new = TALLOC (SCOPE);
	new->symtab = 0;
	new->marked = 0;
	new->block = TALLOC (BLOCK);
	if (current_scope)
		new->block->up = current_scope->block;
	else
		new->block->up = 0;
	new->symtab = & new->block->symtab;
	new->next = sroot;
	sroot = new;
	
	current_scope = sroot;
}

void
close_current_scope ()
{
	if(! current_scope)
		xabort("close_current_scope: nil ???");

	if (current_scope->marked)
		examine_marked ();

	current_scope = sroot = current_scope->next;
}


/*
 * add a new symbol to the marked list for `symbol not found'...
 */

static void
add_marked_sym (lhelm)
LHELM *lhelm;
{
	MARK *new =TALLOC (MARK);

	new->lhelm = lhelm;
	new->next = current_scope->marked;
	current_scope->marked = new;
}


void
examine_marked ()
{
	MARK *mark = current_scope->marked;
	LHELM *lhelm;
	SYMTAB *sym, *osym;
	char *name;
	int nscop;

	while (mark) {
		lhelm = mark->lhelm;
		osym = lhelm->sym;
		name = osym->name;

		if (osym->tag != s_undef)
			xabort ("INTERNAL: examine_marked: still defd");

		sym = find_symbol_anywhere (name, current_scope->block,
					    &nscop);

		if (! sym) {
			a60_error (osym->source, osym->lineno,
				   "undeclared symbol `%s'\n", name);
			nerrors++;
		}
		else {
			xfree ((char *) osym);
			lhelm->sym = sym;
			lhelm->nscop = nscop;
		}

		mark = mark->next;
	}
}


/*
 * climb through the scopes looking for the given symbol.
 */

SYMTAB *
find_symbol_anywhere (name, block, nscop)
char *name;
BLOCK *block;
int *nscop;
{
	SYMTAB *s;
	int up_ref = 0;

	if (! block || ! name)
		return (SYMTAB *) 0;

	s = find_in_symtab (block->symtab, name);
	if (s) {
		*nscop = 0;
		return s;
	}

	/*
	 * extra check for extern reference:
	 * (allow recursion and check for func-var on lefthand)
	 */
	if (block->up && (s = find_in_symtab (block->up->symtab, name)))
		up_ref = 1;

	s = find_symbol_anywhere (name, block->up, nscop);
	(*nscop)++;
	
	if (! s || ! up_ref || ! TIS_PROC(s->type)) {
		/* inc extern reference: */
		block->ext_ref++;
	}

	return s;
}


/*
 * return number of bounds.
 */

int
num_bounds (b)
BOUND *b;
{
	int n;

	for (n=0; b; n++, b=b->next)
		continue;

	return n;
}



/*
 * return number of symbols in symtab.
 */

int
num_symbols (s)
SYMTAB *s;
{
	int n;

	for (n=0; s; n++, s=s->next)
		continue;
	
	return n;
}


/*
 * set all syms in symtab to call_by_value;
 * the syms are freed.
 */

void
set_by_value (symtab, syms)
SYMTAB *symtab, *syms;
{
	SYMTAB *sym, *fnd;

	while (syms) {

		sym = syms;
		fnd = find_in_symtab (symtab, sym->name);
		if (fnd) {
			if (fnd->type == ty_unknown) {
				a60_error (sym->source, sym->lineno,
			   "no specification present for `%s'\n", sym->name);
				nerrors++;
			}
			fnd->tag = s_byvalue;
		}
		else {
			a60_error (sym->source, sym->lineno,
			   "not in parameter list `%s'\n", sym->name);
			nerrors++;
		}
		syms = syms->next;
		xfree ((char *) sym);
	}
}


/*
 * replace the type from syms in symtab;
 * free syms.
 */

void
replace_type (symtab, syms)
SYMTAB *symtab, *syms;
{
	SYMTAB *sym, *fnd;

	while (syms) {

		sym = syms;
		fnd = find_in_symtab (symtab, sym->name);
		if (fnd) {
			if (fnd->type != ty_unknown)
				a60_error ("INTERNAL", 0, 
				   "INTERNAL: replace_type: still defd\n");
			fnd->type = sym->type;
		}
		else {
			a60_error (sym->source, sym->lineno,
			   "not in parameter list `%s'\n", sym->name);
			nerrors++;
		}
		syms = syms->next;
		xfree ((char *) sym);
	}
}


static int
set_idx(symtab, n)
SYMTAB *symtab;
int n;
{
	if (! symtab)
		return n;
	
	symtab->actidx = n;
	return set_idx (symtab->next, n+1);
}

int
set_actidx (symtab)
SYMTAB *symtab;
{
	return set_idx (symtab, 0);
}


/*
 * find the reference for an identifier.
 */

LHELM *
make_var_ref (name, mark)
char *name;
int mark;
{
	int nscop;
	LHELM *new;
	int not_found;
	SYMTAB *sym;

	if (current_scope)
		sym = find_symbol_anywhere (name, current_scope->block,
					    &nscop);
	else
		sym = (SYMTAB *) 0;

	not_found = ! sym;

	if (not_found) {
		if (! mark) {
			a60_error (infname, lineno,
				   "undeclared symbol `%s'\n", name);
			nerrors++;
			return (LHELM *) 0;
		}
		else {
			sym = new_symbol (name, ty_unknown, s_undef);
			nscop = -1;
		}
	}

	new = new_lhelm (sym);
	new->nscop = nscop;

	if (not_found && mark)
		add_marked_sym (new);

	return new;
}

/* end of symtab.c */
