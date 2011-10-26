/* 
 * tclEnv.c --
 *
 *	Tcl support for environment variables, including a setenv
 *	procedure.
 *
 * Copyright 1991 Regents of the University of California
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that this copyright
 * notice appears in all copies.  The University of California
 * makes no representations about the suitability of this
 * software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 *
 * $Id: tclEnv.c,v 1.1.1.1 2001/04/29 20:34:37 karll Exp $
 */

#include "tclInt.h"
#include "tclUnix.h"


/*
 * The structure below is used to keep track of all of the interpereters
 * for which we're managing the "env" array.  It's needed so that they
 * can all be updated whenever an environment variable is changed
 * anywhere.
 */

typedef struct EnvInterp {
    Tcl_Interp *interp;		/* Interpreter for which we're managing
				 * the env array. */
    struct EnvInterp *nextPtr;	/* Next in list of all such interpreters,
				 * or zero. */
} EnvInterp;

static EnvInterp *firstInterpPtr;
				/* First in list of all managed interpreters,
				 * or NULL if none. */

/*
 * Declarations for local procedures defined in this file:
 */

static char *		EnvTraceProc _ANSI_ARGS_((ClientData clientData,
			    Tcl_Interp *interp, char *name1, char *name2,
			    int flags));

/*
 *----------------------------------------------------------------------
 *
 * TclSetupEnv --
 *
 *	This procedure is invoked for an interpreter to make environment
 *	variables accessible from that interpreter via the "env"
 *	associative array.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	The interpreter is added to a list of interpreters managed
 *	by us, so that its view of envariables can be kept consistent
 *	with the view in other interpreters.  If this is the first
 *	call to Tcl_SetupEnv, then additional initialization happens,
 *	such as copying the environment to dynamically-allocated space
 *	for ease of management.
 *
 *----------------------------------------------------------------------
 */

void
TclSetupEnv(interp)
    Tcl_Interp *interp;		/* Interpreter whose "env" array is to be
				 * managed. */
{
    EnvInterp *eiPtr;
    int i;

    /* Next, verify that file descriptors 0, 1 and 2 are connected to something.
     * If not, we open them connected to /dev/null since Tcl assumes that
     * a normal open() will never return 0, 1 or 2
     */
    if (fcntl(0, F_GETFL, 0) < 0 && errno == EBADF) {
	open("/dev/null", O_RDONLY);
    }
    if (fcntl(1, F_GETFL, 0) < 0 && errno == EBADF) {
	open("/dev/null", O_WRONLY);
    }
    if (fcntl(2, F_GETFL, 0) < 0 && errno == EBADF) {
	open("/dev/null", O_WRONLY);
    }

    /*
     * Next, add the interpreter to the list of those that we manage.
     */

    eiPtr = (EnvInterp *) ckalloc(sizeof(EnvInterp));
    eiPtr->interp = interp;
    eiPtr->nextPtr = firstInterpPtr;
    firstInterpPtr = eiPtr;

    /*
     * Store the environment variable values into the interpreter's
     * "env" array, and arrange for us to be notified on future
     * writes and unsets to that array.
     */

    (void) Tcl_UnsetVar2(interp, "env", (char *) NULL, TCL_GLOBAL_ONLY);
    for (i = 0; ; i++) {
	char *p, *p2;

	p = environ[i];
	if (!p || !*p ) {
	    break;
	}
	for (p2 = p; *p2 != '='; p2++) {
	    /* Empty loop body. */
	}
	*p2 = 0;
	(void) Tcl_SetVar2(interp, "env", p, p2+1, TCL_GLOBAL_ONLY);
	*p2 = '=';
    }
    Tcl_TraceVar2(interp, "env", (char *) NULL,
	    TCL_GLOBAL_ONLY | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
	    EnvTraceProc, (ClientData) NULL);
}

/*
 *----------------------------------------------------------------------
 *
 * EnvTraceProc --
 *
 *	This procedure is invoked whenever an environment variable
 *	is modified or deleted.  It propagates the change to the
 *	"environ" array and to any other interpreters for whom
 *	we're managing an "env" array.
 *
 * Results:
 *	Always returns NULL to indicate success.
 *
 * Side effects:
 *	Environment variable changes get propagated.  If the whole
 *	"env" array is deleted, then we stop managing things for
 *	this interpreter (usually this happens because the whole
 *	interpreter is being deleted).
 *
 *----------------------------------------------------------------------
 */

	/* ARGSUSED */
static char *
EnvTraceProc(clientData, interp, name1, name2, flags)
    ClientData clientData;	/* Not used. */
    Tcl_Interp *interp;		/* Interpreter whose "env" variable is
				 * being modified. */
    char *name1;		/* Better be "env". */
    char *name2;		/* Name of variable being modified, or
				 * NULL if whole array is being deleted. */
    int flags;			/* Indicates what's happening. */
{
    /*
     * First see if the whole "env" variable is being deleted.  If
     * so, just forget about this interpreter.
     */

    if (name2 == NULL) {
	register EnvInterp *eiPtr, *prevPtr;

	if ((flags & (TCL_TRACE_UNSETS|TCL_TRACE_DESTROYED))
		!= (TCL_TRACE_UNSETS|TCL_TRACE_DESTROYED)) {
	    panic("EnvTraceProc called with confusing arguments");
	}
	eiPtr = firstInterpPtr;
	if (eiPtr->interp == interp) {
	    firstInterpPtr = eiPtr->nextPtr;
	} else {
	    for (prevPtr = eiPtr, eiPtr = eiPtr->nextPtr; ;
		    prevPtr = eiPtr, eiPtr = eiPtr->nextPtr) {
		if (eiPtr == NULL) {
		    panic("EnvTraceProc couldn't find interpreter");
		}
		if (eiPtr->interp == interp) {
		    prevPtr->nextPtr = eiPtr->nextPtr;
		    break;
		}
	    }
	}
	ckfree((char *) eiPtr);
	return NULL;
    }

    /*
     * If a value is being set, call setenv to do all of the work.
     */

    if (flags & TCL_TRACE_WRITES) {
	setenv(name2, Tcl_GetVar2(interp, "env", name2, TCL_GLOBAL_ONLY), 1);
    }

    if (flags & TCL_TRACE_UNSETS) {
	unsetenv(name2);
    }
    return NULL;
}
