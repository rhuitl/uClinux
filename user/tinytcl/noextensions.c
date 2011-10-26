/*
 * noextensions.c
 *
 *
 * Copyright (c) 2004 Snapgear
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 */
#include "tcl.h"

/* Just do nothing. Extensions are loaded dynamically. */
void init_extensions(Tcl_Interp *interp)
{
}
