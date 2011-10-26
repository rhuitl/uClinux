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
 * bltin.c:					sept '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#include "comm.h"
#include "a60.h"
#include "symtab.h"
#include "util.h"
#include "run.h"
#include "conv.h"
#include "bltin.h"
#include "eval.h"


#define NOT_FOR_MKC_C
/*
 * include common stuff:
 */
#include "a60-mkc.inc"

/* and clear the flag: */
#undef NOT_FOR_MKC_C


/*
 * the predefind functions (procs):
 */

/* ARGSUSED */
static void
bltin_pi (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	DATA *data;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin PI called.\n");
#endif /* DEBUG */

	for (cb=act_cblock; cb && cb->block != sym->block; cb=cb->next)
		continue;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_pi: no block or activation");

	data = (cb->activ)[sym->actidx].data;
	
	data->u.val->u.rval = M_PI;
	data->u.val->valid = 1;
}


/* ARGSUSED */
static void
bltin_rand (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	DATA *data;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin rand called.\n");
#endif /* DEBUG */

	for (cb=act_cblock; cb && cb->block != sym->block; cb=cb->next)
		continue;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_rand: no block or activation");

	data = (cb->activ)[sym->actidx].data;
	
	data->u.val->u.rval = b_rand ();
	data->u.val->valid = 1;
}


/*
 * hmmm - the vprint proc; this one with a variable number of arguments.
 * we'll see
 */

/* ARGSUSED */
static void
bltin_vprint (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	DATA *data;
	EVALELM ev;
	int i;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin vprint called (%d arguments).\n", nparm);
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ) {
		/* no activation means no parameter -> newline only. */
		printf ("\n");
		return;
	}

	for (i=0; i<nparm; i++) {
		data = (cb->activ)[i].data;
		do_eval_pexpr (& data->u.pexpr);
		DO_DEREF(data->u.pexpr.expr->source, 
			  data->u.pexpr.expr->lineno);
		ev = * POP_EVALST;

		if (ev.tag == ev_ival) {
			printf ("  %15ld ", ev.u.ival);
		}
		else if (ev.tag == ev_rval) {
#ifdef sun
			/* 
			 * printf ("%g",  - 0.0) gives: -0
			 * may be a ``Klassiker'' by sun only...
			 * i like to prevent this:
			 */
			if (ev.u.rval == 0.0)
				ev.u.rval = (int) ev.u.rval;
#endif
			printf ("  %15.7e ", ev.u.rval);
		}
		else if (ev.tag == ev_string) {
			printf ("%s", ev.u.string);
		}
		else if (ev.tag == ev_bool) {
			printf (" %s ", (ev.u.bool) ? "T" : "F");
		}
		else {
			a60_error (ev.source, ev.lineno,
			   "vprint cannot handle parameter of type `%s'\n",
				   eval_tag_name[ev.tag]);
			xabort ("runtime error");
		}
		fflush (stdout);
	}

	printf ("\n");
	fflush (stdout);
}


/* ARGSUSED */
static void
bltin_outreal (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	DATA *chandata, *valdata;
	long chan;
	double val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin outreal called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_outreal: no block or activation");

	chandata = (cb->activ)[0].data;
	valdata = (cb->activ)[1].data;

	chan = chandata->u.val->u.ival;
	val = valdata->u.val->u.rval;

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_outreal: chan %d; value %g\n",
			chan, val);
#endif /* DEBUG */

	b_outreal (chan, val);
}


/* ARGSUSED */
static void
bltin_outinteger (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	long chan, val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin outinteger called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_outinteger: no block or activation");

	chan = (cb->activ)[0].data->u.val->u.ival;
	val = (cb->activ)[1].data->u.val->u.ival;

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_outinteger: chan %ld; value %ld\n",
			chan, val);
#endif /* DEBUG */

	b_outint (chan, val);
}


/* ARGSUSED */
static void
bltin_outstring (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	long chan;
	PEXPR *pexpr;
	EVALELM ev;
	char *val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin outstring called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_outstring: no block or activation");

	chan = (cb->activ)[0].data->u.val->u.ival;
	pexpr = & (cb->activ)[1].data->u.pexpr;
	do_eval_pexpr (pexpr);
	ev = * POP_EVALST;
	if (ev.tag != ev_string) {
		a60_error (ev.source, ev.lineno,
	   "actual parameter does not match formal\n");
		xabort ("runtime error");
	}
	val = ev.u.string;

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_outstring: chan %ld; value %s\n",
			chan, (val) ? val : "");
#endif /* DEBUG */
	b_outstr (chan, val);
}


/* ARGSUSED */
static void
bltin_outsymbol (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	PEXPR *pexpr;
	EVALELM ev;
	long chan, idx;
	char *val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin outsymbol called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_outsymbol: no block or activation");

	chan = (cb->activ)[0].data->u.val->u.ival;
	idx = (cb->activ)[2].data->u.val->u.ival;

	pexpr = & (cb->activ)[1].data->u.pexpr;
	do_eval_pexpr (pexpr);
	ev = * POP_EVALST;
	if (ev.tag != ev_string) {
		a60_error (ev.source, ev.lineno,
	   "actual parameter does not match formal\n");
		xabort ("runtime error");
	}
	val = ev.u.string;

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_outsymbol: chan %ld; str %s; idx %ld\n",
			chan, (val) ? val : "", idx);
#endif /* DEBUG */

	b_outsym (chan, val, idx);
}


/* ARGSUSED */
static void
bltin_insymbol (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	PEXPR *pexpr;
	EVALELM ev, *evp;
	long chan, val;
	char *str;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin insymbol called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_insymbol: no block or activation");

	chan = (cb->activ)[0].data->u.val->u.ival;

	pexpr = & (cb->activ)[1].data->u.pexpr;
	do_eval_pexpr (pexpr);
	ev = * POP_EVALST;
	if (ev.tag != ev_string) {
		a60_error (ev.source, ev.lineno,
	   "actual parameter does not match formal\n");
		xabort ("runtime error");
	}
	str = ev.u.string;

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_insymbol: chan %ld; str %s:\n",
			chan, (str) ? str : "");
#endif /* DEBUG */

	if (run_with_xa60) {
		xabort ("xa60: insymbol: cannot send input - sorry.");
		/* not reached */
		return;
	}

	val = b_insym (chan, str);

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_insymbol: val %ld\n", val);
#endif /* DEBUG */
 
	pexpr = & (cb->activ)[2].data->u.pexpr;
	do_eval_pexpr (pexpr);

	evp = PUSH_EVALST ("internal", 0, ev_ival);
	evp->u.ival = val;

	assign_vals (0);
}


/* ARGSUSED */
static void
bltin_inreal (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	PEXPR *pexpr;
	EVALELM *evp;
	long chan;
	double val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin inreal called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_inreal: no block or activation");

	chan = (cb->activ)[0].data->u.val->u.ival;
#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_inreal: chan %ld;\n", chan);
#endif /* DEBUG */

	if (run_with_xa60) {
		xabort ("xa60: inreal: cannot send input - sorry.");
		/* not reached */
		return;
	}

	val = b_inreal (chan);
	
#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_inreal: val %e\n", val);
#endif /* DEBUG */

	pexpr = & (cb->activ)[1].data->u.pexpr;
	do_eval_pexpr (pexpr);

	evp = PUSH_EVALST ("internal", 0, ev_rval);
	evp->u.rval = val;

	assign_vals (0);
}


/* ARGSUSED */
static void
bltin_length (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	PEXPR *pexpr;
	EVALELM ev;
	DATA *data;
	long len;
	char *val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin length called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_length: no block or activation");

	pexpr = & (cb->activ)[0].data->u.pexpr;
	do_eval_pexpr (pexpr);
	ev = * POP_EVALST;
	if (ev.tag != ev_string) {
		a60_error (ev.source, ev.lineno,
	   "actual parameter does not match formal\n");
		xabort ("runtime error");
	}
	val = ev.u.string;

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_length: string `%s'\n", (val) ? val : "");
#endif /* DEBUG */

	len = b_length (val);

	/*
	 * now assign the return value:
	 */
	
	for (cb=act_cblock; cb && cb->block != sym->block; cb=cb->next)
		continue;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_length: no block or activation");

	data = (cb->activ)[sym->actidx].data;
	
	data->u.val->u.ival = len;
	data->u.val->valid = 1;
}


/* ARGSUSED */
static void
bltin_print (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	long f1, f2;
	double val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin print called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_print: no block or activation");

	val = (cb->activ)[0].data->u.val->u.rval;
	f1 = (cb->activ)[1].data->u.val->u.ival;
	f2 = (cb->activ)[2].data->u.val->u.ival;

#ifdef DEBUG
	if (do_debug)
		printf ("** bltin_print: val %g; format: %ld  %ld\n",
			val, f1, f2);
#endif /* DEBUG */

	b_print (val, f1, f2);
}





/* ARGSUSED */
static void
bltin_write (sym, nparm)
SYMTAB *sym;
int nparm;
{
	CBLOCK *cb;
	PEXPR *pexpr;
	EVALELM ev;
	char *val;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin write called.\n");
#endif /* DEBUG */

	cb = act_cblock;

	if (!cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: bltin_write: no block or activation");

	pexpr = & (cb->activ)[0].data->u.pexpr;
	do_eval_pexpr (pexpr);
	ev = * POP_EVALST;
	if (ev.tag != ev_string) {
		a60_error (ev.source, ev.lineno,
	   "actual parameter does not match formal\n");
		xabort ("runtime error");
	}
	val = ev.u.string;

	printf ("%s", val);
	fflush (stdout);
}


/*
 * get the parameter of the function and the data space for the
 * return value.
 */

static void
get_val_and_rdata (sym, val_data, ret_data)
SYMTAB *sym;
DATA **val_data, **ret_data;
{
	CBLOCK *cb;
	DATA *data;

#ifdef DEBUG
	if (do_debug)
		printf ("** builtin func `%s' called.\n", sym->name);
#endif /* DEBUG */

	cb = act_cblock;

	if (! cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: get_val_and_rdata: no block or activation");

	data = (cb->activ)[0].data;
	* val_data = data;

	/*
	 * now get the return data space:
	 */
	
	for (cb=act_cblock; cb && cb->block != sym->block; cb=cb->next)
		continue;

	if (! cb || ! cb->block || ! cb->activ)
		xabort ("INTERNAL: get_val_and_rdata: no block or activation");

	data = (cb->activ)[sym->actidx].data;

	* ret_data = data;
}


/*
 * builtin real functions:
 */

#define BLTIN_MATH_HEAD(b) \
/* ARGSUSED */ \
static void \
b (sym, nparm) \
SYMTAB *sym; \
int nparm; \
{ \
	DATA *val_data, *ret_data; \
	double x; \
 \
	get_val_and_rdata (sym, &val_data, &ret_data); \
	x = val_data->u.val->u.rval;

#define BLTIN_MATH_TAIL \
	ret_data->u.val->u.rval = x; \
	ret_data->u.val->valid = 1; \
}



/*
 * and now the bltin functions:
 */

BLTIN_MATH_HEAD(bltin_abs)
	if (x < 0.0)
		x = -x;
BLTIN_MATH_TAIL
	
BLTIN_MATH_HEAD(bltin_sqrt)
	if (x < 0.0) {
		a60_error (sym->source, sym->lineno,
			   "argument of sqrt is negative (%g).\n", x);
			   xabort ("runtime error");
	}
	x = sqrt (x);
BLTIN_MATH_TAIL

BLTIN_MATH_HEAD(bltin_sin)
	x = sin (x);
BLTIN_MATH_TAIL

BLTIN_MATH_HEAD(bltin_cos)
	x = cos (x);
BLTIN_MATH_TAIL

BLTIN_MATH_HEAD(bltin_arctan)
	x = atan (x);
BLTIN_MATH_TAIL

BLTIN_MATH_HEAD(bltin_ln)
	if (x < 0.0) {
		a60_error (sym->source, sym->lineno,
			   "argument of log is negative (%g).\n", x);
			   xabort ("runtime error");
	}
	x = log (x);
BLTIN_MATH_TAIL

BLTIN_MATH_HEAD(bltin_exp)
	x = exp (x);
BLTIN_MATH_TAIL


/*
 * sign:
 */

/* ARGSUSED */
static void
bltin_sign (sym, nparm)
SYMTAB *sym;
int nparm;
{
	DATA *val_data, *ret_data; double x;

#ifdef DEBUG
	if (do_debug) printf ("* bltin sign called ...\n");
#endif /* DEBUG */
	get_val_and_rdata (sym, &val_data, &ret_data);
	x = val_data->u.val->u.rval;

	ret_data->u.val->u.ival = b_sign (x);
	ret_data->u.val->valid = 1;
}


/*
 * entier:
 */

/* ARGSUSED */
static void
bltin_entier (sym, nparm)
SYMTAB *sym;
int nparm;
{
	DATA *val_data, *ret_data; double x;

#ifdef DEBUG
	if (do_debug) printf ("* bltin entier called ...\n");
#endif /* DEBUG */

	get_val_and_rdata (sym, &val_data, &ret_data);
	x = val_data->u.val->u.rval;
	
	ret_data->u.val->u.ival = b_entier (x);
	ret_data->u.val->valid = 1;
}



/*
 * init the predefined symbols; 
 */

static SYMTAB *
init_new_symbol (name, type, bltin)
char *name;
ENUM type_tag type;
void (* bltin) ();
{
	PPROC *new = TALLOC (PPROC);
	SYMTAB *psym = new_symbol (name, type, s_defined);
	psym->source = "<internal>";
	psym->lineno = 0;
	examine_and_append_symtab (current_scope->symtab, psym);
	psym->block = current_scope->block;
	
	open_new_scope ();
	psym->u.pproc = new;
	psym->u.pproc->nparm = 0;
	psym->u.pproc->block = current_scope->block;
	
	psym->u.pproc->bltin = bltin;
	close_current_scope ();
	
	return psym;
}

static SYMTAB *
init_parmsym (name, type, tag)
char *name;
ENUM type_tag type;
ENUM sym_tag tag;
{
	SYMTAB *new = new_symbol (name, type, tag);

	return new;
}


/*
 * initialize builtin function `PI':
 *
 * 	'real' 'procedure' PI;
 * 		PI := 3.14;
 * 		
 */

static void
init_pi ()
{
	SYMTAB *sym;

	sym = init_new_symbol ("PI", ty_real_proc, bltin_pi);
	sym->u.pproc->block->nact = 0;
}


/*
 * initialize build in function `rand':
 *
 * 	'real' 'procedure' rand;
 * 		'code';
 * 		
 */

static void
init_rand ()
{
	SYMTAB *sym;

	sym = init_new_symbol ("rand", ty_real_proc, bltin_rand);
	sym->u.pproc->block->nact = 0;
}


/*
 * initialize builtin function `print':
 *
 * 	'procedure' printf (....);
 * 		'code';
 */

static void
init_vprint ()
{
	SYMTAB *sym;

	sym = init_new_symbol ("vprint", ty_proc, bltin_vprint);
	sym->u.pproc->nparm = -1;
}


/*
 * initialize builtin function `outreal':
 *
 * 	'procedure' outreal (channel, value);
 *	'value' channel, value;
 *	'integer' channel;
 *	'real' value;
 * 		'code';
 * 		
 */

static void
init_outreal ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("outreal", ty_proc, bltin_outreal);
	parmsym = init_parmsym ("channel", ty_integer, s_byvalue);
	parmsym->block = sym->u.pproc->block;
	parmsym->next = init_parmsym ("source", ty_real, s_byvalue);
	parmsym->next->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 2;
	sym->u.pproc->nparm = 2;
}


/*
 * initialize builtin function `outinteger':
 *
 * 	'procedure' outinteger (channel, value);
 *	'value' channel, value;
 *	'integer' channel, value;
 * 		'code';
 * 		
 */

static void
init_outinteger ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("outinteger", ty_proc, bltin_outinteger);
	parmsym = init_parmsym ("channel", ty_integer, s_byvalue);
	parmsym->block = sym->u.pproc->block;
	parmsym->next = init_parmsym ("source", ty_integer, s_byvalue);
	parmsym->next->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 2;
	sym->u.pproc->nparm = 2;
}


/*
 * initialize builtin function `outstring':
 *
 * 	'procedure' outstring (channel, value);
 *	'value' channel;
 *	'integer' channel;
 *	'string' value;
 * 		'code';
 * 		
 */

static void
init_outstring ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("outstring", ty_proc, bltin_outstring);
	parmsym = init_parmsym ("channel", ty_integer, s_byvalue);
	parmsym->block = sym->u.pproc->block;
	parmsym->next = init_parmsym ("source", ty_string, s_byname);
	parmsym->next->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 2;
	sym->u.pproc->nparm = 2;
}


/*
 * initialize builtin function `outsymbol':
 *
 * 	'procedure' outsymbol (channel, string, source);
 *	'value' channel, source;
 *	'integer' channel, source;
 *	'string' string;
 * 		'code';
 * 		
 */

static void
init_outsymbol ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("outsymbol", ty_proc, bltin_outsymbol);
	parmsym = init_parmsym ("channel", ty_integer, s_byvalue);
	parmsym->block = sym->u.pproc->block;
	parmsym->next = init_parmsym ("string", ty_string, s_byname);
	parmsym->next->block = sym->u.pproc->block;
	parmsym->next->next = init_parmsym ("source", ty_integer, s_byvalue);
	parmsym->next->next->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 3;
	sym->u.pproc->nparm = 3;
}


/*
 * initialize builtin fucntion `insymbol':
 *
 * 	'integer' 'procedure' insymbol (channel, string, value);
 *	'value' channel;
 *	'integer' channel, value;
 *	'string' string;
 * 		'code';
 * 		
 */

static void
init_insymbol ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("insymbol", ty_proc, bltin_insymbol);
	parmsym = init_parmsym ("channel", ty_integer, s_byvalue);
	parmsym->block = sym->u.pproc->block;
	parmsym->next = init_parmsym ("string", ty_string, s_byname);
	parmsym->next->block = sym->u.pproc->block;
	parmsym->next->next = init_parmsym ("value", ty_integer, s_byname);
	parmsym->next->next->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 3;
	sym->u.pproc->nparm = 3;
}


/*
 * initialize builtin fucntion `inreal':
 *
 * 	'procedure' inreal (channel, value);
 *	'value' channel;
 *	'integer' channel;
 *	'real' value;
 * 		'code';
 * 		
 */

static void
init_inreal ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("inreal", ty_proc, bltin_inreal);
	parmsym = init_parmsym ("channel", ty_integer, s_byvalue);
	parmsym->block = sym->u.pproc->block;
	parmsym->next = init_parmsym ("value", ty_real, s_byname);
	parmsym->next->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 2;
	sym->u.pproc->nparm = 2;
}


/*
 * initialize builtin function `print':
 *
 * 	'procedure' print (value, f1, f2);
 *	'value' value, f1, f2;
 *	'real' value;
 *	'integer' f1, f2;
 * 		'code';
 */

static void
init_print ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("print", ty_proc, bltin_print);
	parmsym = init_parmsym ("value", ty_real, s_byvalue);
	parmsym->block = sym->u.pproc->block;
	parmsym->next = init_parmsym ("f1", ty_integer, s_byvalue);
	parmsym->next->block = sym->u.pproc->block;
	parmsym->next->next = init_parmsym ("f2", ty_integer, s_byvalue);
	parmsym->next->next->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 3;
	sym->u.pproc->nparm = 3;
}


/*
 * initialize builtin function `length':
 *
 * 	'integer' 'procedure' length (string);
 *	'string' string;
 * 		'code';
 * 		
 */

static void
init_length ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("length", ty_int_proc, bltin_length);
	parmsym = init_parmsym ("string", ty_string, s_byname);
	parmsym->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 1;
	sym->u.pproc->nparm = 1;
}


/*
 * initialize build-in function `write':
 *
 * 	'integer' 'procedure' write (string);
 *	'string' string;
 * 		'code';
 */

static void
init_write ()
{
	SYMTAB *sym, *parmsym;

	sym = init_new_symbol ("write", ty_proc, bltin_write);
	parmsym = init_parmsym ("string", ty_string, s_byname);
	parmsym->block = sym->u.pproc->block;
	set_actidx (parmsym);
	sym->u.pproc->block->symtab = parmsym;
	sym->u.pproc->block->nact = 1;
	sym->u.pproc->nparm = 1;
}


/*
 * initialize the bltin simple functions:
 *
 * 	<value> 'procedure' func (x);
 * 	'value' x;
 * 	'real' x;
 * 		'code';
 *
 * this is for abs(), sign(), sqrt(), sin(), cos(), arctan(),
 * ln(), exp();
 */

#define INIT_SFUNC(f,s,rty,ty,b) \
static void \
f () \
{ \
	SYMTAB *sym, *parmsym; \
 \
	sym = init_new_symbol (s, rty, b); \
	parmsym = init_parmsym ("value", ty, s_byvalue); \
	parmsym->block = sym->u.pproc->block; \
	set_actidx (parmsym); \
	sym->u.pproc->block->symtab = parmsym; \
	sym->u.pproc->block->nact = 1; \
	sym->u.pproc->nparm = 1; \
}

INIT_SFUNC(init_entier, "entier", ty_int_proc, ty_real, bltin_entier)
INIT_SFUNC(init_abs, "abs", ty_real_proc, ty_real, bltin_abs)
INIT_SFUNC(init_sign, "sign", ty_int_proc, ty_real, bltin_sign)
INIT_SFUNC(init_sqrt, "sqrt", ty_real_proc, ty_real, bltin_sqrt)
INIT_SFUNC(init_sin, "sin", ty_real_proc, ty_real, bltin_sin)
INIT_SFUNC(init_cos, "cos", ty_real_proc, ty_real, bltin_cos)
INIT_SFUNC(init_arctan, "arctan", ty_real_proc, ty_real, bltin_arctan)
INIT_SFUNC(init_ln, "ln", ty_real_proc, ty_real, bltin_ln)
INIT_SFUNC(init_exp, "exp", ty_real_proc, ty_real, bltin_exp)


void
init_bltin ()
{
	init_pi ();
	init_rand ();
	init_vprint ();
	init_write ();
	init_outreal ();
	init_outinteger ();
	init_outstring ();
	init_outsymbol ();
	init_insymbol ();
	init_inreal ();
	init_print ();
	init_length ();
	init_entier ();
	init_abs ();
	init_sign ();
	init_sqrt ();
	init_sin ();
	init_cos ();
	init_arctan ();
	init_ln ();
	init_exp ();
}

/* end of bltin.c */
