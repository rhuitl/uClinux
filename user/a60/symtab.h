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
 * symtab.h:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef SYMTAB_H_HOOK
#define SYMTAB_H_HOOK

#include "type.h"

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


extern char *sym_tag_name[];


enum sym_tag {
	s_defined,
	s_undef,
	s_byname,
	s_byvalue,
	S_LAST_SYM_TAG
};

#define SIS_PARM(s)	((s) == s_byname || (s) == s_byvalue)


typedef struct _fixval {
	union {
		struct _tree *stmt;		/* target for ty_label */
		struct _symtab *symtab;		/* target for ty_switch */
	} u;
} FIXVAL;


typedef struct _bound {
	struct _expr *low, *high;		/* declataion expr */
	struct _bound *next;
} BOUND;


typedef struct _array {
	/* **** long dim ? **** */
	int dim;
	struct _bound *bound;
} ARRAY;


typedef struct _pproc {
	int nparm;				/* number of parameter */
	struct _block *block;			/* pseudo block */
#ifdef __STDC__
	void (* bltin) (struct _symtab *, int);
#else
	void (* bltin)();			/* builtin function */
#endif
} PPROC;


/* store own-marked activations here: */
typedef struct _owndata {
	struct _data *data;
	struct _arract *arract;
} OWNDATA;


/*
 * the general symbol table entry;
 * linked with ``next'' this is a symbol table.
 */

typedef struct _symtab {
	ENUM sym_tag tag;
	ENUM type_tag type;
	char *name;
	char *source;				/* source file */
	int lineno;				/* definition lineno. */
	int actidx;				/* index in activation */
	int own;				/* static storage */
	struct _owndata odata;			/* data for own symbols */
	union {
		struct _fixval *fixval;
		struct _array *arr;
		struct _pproc *pproc;
		/* switch at parse time: */
		struct _expr *dexpr;		/* list of design. expr */
	} u;
	struct _block *block;			/* ptr to block of symbol */
	struct _symtab *next;
} SYMTAB;


/*
 * this is an element for the temporary list of unresolved symbols at
 * parse time.
 */
typedef struct _mark {
	struct _lhelm *lhelm;
	struct _mark *next;
} MARK;


/*
 * symtab points to ``&scope->block->symtab''
 */
typedef struct _scope {
	struct _symtab **symtab;
	struct _mark *marked;
	struct _block *block;
	struct _scope *next;
} SCOPE;


extern SCOPE *current_scope;
extern int unary_minus;

extern char *cleanup_identifier P((char *));
extern SYMTAB *new_symbol P((char *, enum type_tag, enum sym_tag));
extern SYMTAB *add_to_symtab P((SYMTAB **, char *, enum sym_tag));
extern SYMTAB *find_in_symtab P((SYMTAB *, char *));
extern SYMTAB *add_symbol P((SYMTAB **, SYMTAB *));
extern void append_symtab P((SYMTAB **, SYMTAB *));
extern void examine_and_append_symtab P((SYMTAB **, SYMTAB *));
extern void sym_all_type P((SYMTAB *, enum type_tag, int));
extern int set_actidx P((struct _symtab *));

extern void print_indent_symtab P((SYMTAB *, int));
extern void print_symtab P((SYMTAB *));

extern void check_decl P((SYMTAB *));
extern void open_new_scope P((void));
extern void close_current_scope P((void));
extern void examine_marked P((void));
extern SYMTAB *find_symbol_anywhere P((char *, struct _block *, int *));
extern int num_bounds P((BOUND *));
extern int num_symbols P((SYMTAB *));
extern void set_by_value P((SYMTAB *, SYMTAB *));
extern void replace_type  P((SYMTAB *, SYMTAB *));
extern void set_unknown_to_real P((SYMTAB *));
extern struct _lhelm *make_var_ref P((char *, int));


#undef P

#endif /* SYMTAB_H_HOOK */
