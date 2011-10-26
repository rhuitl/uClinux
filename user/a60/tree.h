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
 * tree.h:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef TREE_H_HOOK
#define TREE_H_HOOK

#include "block.h"
#include "symtab.h"
#include "type.h"
#include "expr.h"

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


enum tree_tag {
	t_block,
	t_label,
	t_dummy_stmt,
	t_goto_stmt,
	t_assign_stmt,
	t_if_stmt,
	t_proc_stmt,
	t_for_stmt,
	T_LAST_TREE_TAG
};

extern char *tree_tag_name[];


typedef struct _mindex {
	EXPR *expr;
	struct _mindex *next;
} MINDEX;


typedef struct _lhelm {
	SYMTAB *sym;
	MINDEX *mindex;
	union {
		struct _funcall *fcall;
	} u;
	int nscop;			/* number of scopes */
	char *source;
	int lineno;
	struct _lhelm *next;
} LHELM;


typedef struct _assign {
	LHELM *lhelm;
	EXPR *expr;
} ASSIGN;

typedef struct _ifstmt {
	struct _expr *cond;
	struct _tree *tthen, *telse; 
} IFSTMT;

typedef struct _funcall {
	struct _symtab *sym;		/* proc symbol (name) */
	int nparm;			/* number of parameter */
	struct _expr *parm;		/* parameter list */
} FUNCALL;


/*
 * for statement: the variable, the list of elements and
 * the body.
 */

enum forelm_tag {
        fe_expr,
        fe_until,
        fe_while
};

typedef struct _forelm {
	ENUM forelm_tag tag;		/* expr / until / while */
	struct _expr *expr[3];		/* parameter (left to right) */
	struct _forelm *next;		/* next loop elm */
} FORELM;

typedef struct _forstmt {
	struct _lhelm *lvar;		/* run variable */
	struct _forelm *forelm;		/* elements of the for_list */
	struct _tree *stmt;		/* body of the loop */
} FORSTMT;


/*
 * the tree struct over all; this is globally a stmt or a block;
 */

typedef struct _tree {
	ENUM tree_tag tag;
	union {
		BLOCK *block;		/* block entry */
		SYMTAB *symbol;		/* label */
		EXPR *dexpr;		/* goto destination */
		ASSIGN *ass;
		IFSTMT *ifstmt;
		FORSTMT *forstmt;
		FUNCALL *funcall;
	} u;
	char *source;
	int lineno;
	void (*runme)();
	int is_cont;			/* next ptr is continuation */
	struct _tree *next;
} TREE;


/* external's : */

extern TREE *new_tree P((enum tree_tag));
extern LHELM *new_lhelm P((SYMTAB *));
extern MINDEX *new_mindex P((EXPR *));
extern FUNCALL *new_funcall P((SYMTAB *, EXPR *));

extern void print_indent P((int));
extern void print_tree P((struct _tree *));
extern void print_indent_tree P((struct _tree *, int, int));
extern void print_mindex P((struct _mindex *));

extern void append_stmt P((TREE **, TREE *, int));
extern struct _tree * new_if_stmt P((struct _expr *));
extern struct _tree * new_assign_stmt P((struct _lhelm *, struct _expr *));
#if 0
extern struct _tree * new_goto_stmt P((struct _symtab *));
#else
extern struct _tree * new_goto_stmt P((struct _expr *));
#endif

#undef P

#endif /* TREE_H_HOOK */
