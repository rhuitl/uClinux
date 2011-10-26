/*
 * tclLoad.c
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
#include "tclExtdInt.h"
#include "tclLoad.h"

/*
 *----------------------------------------------------------------------
 *
 * Tcl_LoadObjCmd --
 *
 *	This procedure is invoked to process the "load" Tcl command.
 *	See the user documentation for details on what it does.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	See the user documentation.
 *
 *----------------------------------------------------------------------
 */

int
Tcl_LoadCmd(ClientData dummy, Tcl_Interp *interp, int argc, char **argv)
{
    char *modname;
    char *pkgname = 0;
    char *initname;
    int code;
    Tcl_LoadHandle handle;
    Tcl_FSUnloadFileProc *unloader = 0;
    Tcl_PackageInitProc *initProc;

    if (argc < 2 || argc > 3) {
        Tcl_AppendResult (interp, "bad # args: ", argv[0], 0);
	return TCL_ERROR;
    }

    modname = argv[1];

    if (argc >= 3) {
	pkgname = argv[2];
    }

    /* REVISIT: Should make sure that we aren't loading this file twice */

    /*
     * The desired file isn't currently loaded, so load it.
     */

    /*
     * Call platform-specific code to load the package and find the
     * two initialization procedures.
     */

    code = TclpDlopen(interp, modname, &handle, &unloader);
    if (code != TCL_OK) {
	return TCL_ERROR;
    }

    /*
     * There must be an init function $(package)_Init which initialises the package.
     */

    if (pkgname) {
	initname = ckalloc(strlen(pkgname) + 6);
	strcpy(initname, pkgname);
	strcat(initname, "_Init");
    }
    else {
	/* We determine the init function from the module name */
	char *pt;

	/* Remove any path */
	pkgname = strrchr(modname, '/');

	if (pkgname) {
	    pkgname++;
	}
	else {
	    pkgname = modname;
	}

	/* Remove any lib prefix */
	if (strncmp(pkgname, "lib", 3) == 0) {
	    pkgname += 3;
	}

	initname = ckalloc(strlen(pkgname) + 6);
	strcpy(initname, pkgname);

	/* Now remove any extension */
	pt = strchr(initname, '.');
	if (pt) {
	    *pt = 0;
	}
	strcat(initname, "_Init");
    }

    initProc = TclpFindSymbol(interp, handle, initname);
    if (initProc == 0) {
	Tcl_AppendResult(interp, "couldn't find procedure ", initname, " in ", modname, 0);
	if (unloader != NULL) {
	    (*unloader)(handle);
	}
	ckfree(initname);
	return TCL_ERROR;
    }

    /*
     * Invoke the package's initialization procedure (either the
     * normal one or the safe one, depending on whether or not the
     * interpreter is safe).
     */

    code = initProc(interp);

    ckfree(initname);

    if (code != TCL_OK) {
	Tcl_AppendResult(interp, "failed to execute init procedure in ", modname, 0);
	if (unloader != NULL) {
	    (*unloader)(handle);
	}
    }

    return code;
}
