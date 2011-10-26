/* 
 * tclTest.c --
 *
 *	Test driver for TCL.
 *
 * Copyright 1987-1991 Regents of the University of California
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appears in all copies.  The University of California
 * makes no representations about the suitability of this
 * software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 *
 * $Id: tinytcl.c,v 1.2 2001/04/29 20:56:17 karll Exp $
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "tcl.h"
#include "tclExtdInt.h"
#ifdef DEBUGGER
#include "Dbg.h"
#endif

//#include <alloc.h>

/* From generated load_extensions.c */
void init_extensions(Tcl_Interp *interp);

Tcl_Interp *interp;
Tcl_CmdBuf buffer;
char dumpFile[100];
int quitFlag = 0;

char initCmd[] =
    "puts stdout \"\nEmbedded Tcl 6.8.0\n\"";//; source tcl_sys/autoinit.tcl";

	/* ARGSUSED */
#ifdef TCL_MEM_DEBUG
int
cmdCheckmem(clientData, interp, argc, argv)
    ClientData clientData;
    Tcl_Interp *interp;
    int argc;
    char *argv[];
{
    if (argc != 2) {
	Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
		" fileName\"", (char *) NULL);
	return TCL_ERROR;
    }
    strcpy(dumpFile, argv[1]);
    quitFlag = 1;
    return TCL_OK;
}
#endif

int
main(int argc, char *argv[])
{
    char line[1000], *cmd;
    int result, gotPartial;
	FILE *in;
	FILE *out;

    interp = Tcl_CreateInterp();
#ifdef TCL_MEM_DEBUG
    Tcl_InitMemory(interp);
#endif
    Tcl_InitDebug (interp);
    TclX_InitGeneral (interp);
#ifdef DEBUGGER
    Dbg_Init(interp);
#endif

    /* Init any static extensions */
    init_extensions(interp);

#ifdef TCL_MEM_DEBUG
    Tcl_CreateCommand(interp, "checkmem", cmdCheckmem, (ClientData) 0,
	    (Tcl_CmdDeleteProc *) NULL);
#endif

    buffer = Tcl_CreateCmdBuf();

    if (argc > 1 && strcmp(argv[1], "-") != 0) {
	char *filename = argv[1];
	char *args;

	/* Before we eval the file, create an argv global containing
	 * the remaining arguments
	 */
	
	args = Tcl_Merge(argc - 2, argv + 2);
	Tcl_SetVar(interp, "argv", args, TCL_GLOBAL_ONLY);
	ckfree(args);

	result = Tcl_EvalFile(interp, filename);
	if (result != TCL_OK) {
	    /* And make sure we print an informative error if something goes wrong */
	    Tcl_AddErrorInfo(interp, "");
	    printf("%s\n", Tcl_GetVar(interp, "errorInfo", TCL_LEAVE_ERR_MSG));
	    exit(1);
	}
	exit(0);
    }
    else {
	/* Are we in interactive mode or script from stdin mode? */
	int noninteractive = (argc > 1);
	in = stdin;
	out = stdout;

#ifndef TCL_GENERIC_ONLY
	if (!noninteractive) {
	    result = Tcl_Eval(interp, initCmd, 0, (char **) NULL);
	    if (result != TCL_OK) {
		printf("%s\n", interp->result);
		exit(1);
	    }
	}
#endif
	gotPartial = 0;
	while (1) {
	    clearerr(in);
	    if (!gotPartial) {
		if (!noninteractive)  {
			fputs("% ", out);
		}
		fflush(out);
	    }
	    if (fgets(line, 1000, in) == NULL) {
		if (!gotPartial) {
		    exit(0);
		}
		line[0] = 0;
	    }
	    cmd = Tcl_AssembleCmd(buffer, line);
	    if (cmd == NULL) {
		gotPartial = 1;
		continue;
	    }

	    gotPartial = 0;
#ifdef TCL_NO_HISTORY
	    result = Tcl_Eval(interp, cmd, 0, (char **)NULL);
#else
		result = Tcl_RecordAndEval(interp, cmd, 0);
#endif
	    if (result == TCL_OK) {
		if ((*interp->result != 0) && !noninteractive){
		    printf("%s\n", interp->result);
		}
		if (quitFlag) {
		    Tcl_DeleteInterp(interp);
		    Tcl_DeleteCmdBuf(buffer);
    #ifdef TCL_MEM_DEBUG
		    Tcl_DumpActiveMemory(dumpFile);
    #endif
		    exit(0);
		}
	    } else {
		if (result == TCL_ERROR) {
		    printf("Error");
		} else {
		    printf("Error %d", result);
		}
		if (*interp->result != 0) {
		    printf(": %s\n", interp->result);
		} else {
		    printf("\n");
		}
	    }
	}
    }
}
