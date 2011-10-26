#ifndef TCL_LOAD_H
#define TCL_LOAD_H

/*
 * tclLoad.h
 *
 * Dynamic loading of tcl modules.
 *
 * Copyright (c) 1995-1997 Sun Microsystems, Inc.
 * This file was integrated from tcl to tinytcl by Snapgear.
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 */

#include "tclInt.h"

typedef struct Tcl_LoadHandle_ *Tcl_LoadHandle;
typedef void Tcl_FSUnloadFileProc(Tcl_LoadHandle loadHandle);
typedef int Tcl_PackageInitProc(Tcl_Interp *interp);

int TclpDlopen(Tcl_Interp *interp, char *path, Tcl_LoadHandle *loadHandle, Tcl_FSUnloadFileProc **unloadProcPtr);
Tcl_PackageInitProc* TclpFindSymbol(Tcl_Interp *interp, Tcl_LoadHandle loadHandle, const char *symbol);
void TclpUnloadFile(Tcl_LoadHandle loadHandle);

#endif
