/* Dbg_cmd.c - Tcl Debugger default command, used if app writer wants a
			   quick and reasonable default.

Written by: Don Libes, NIST, 3/23/93

Design and implementation of this program was paid for by U.S. tax
dollars.  Therefore it is public domain.  However, the author and NIST
would appreciate credit if this program or parts of it are used.

*/

#include "tclInt.h"
#include "Dbg.h"

char *Dbg_DefaultCmdName = "debug";

/*ARGSUSED*/
static int
App_DebugCmd(clientData, interp, argc, argv)
ClientData clientData;
Tcl_Interp *interp;
int argc;
char **argv;
{
	int now = 0;	/* soon if 0, now if 1 */

	if (argc > 3) goto usage;

	argv++;

	while (*argv) {
		if (0 == strcmp(*argv,"-now")) {
			now = 1;
			argv++;
		}
		else break;
	}

	if (!*argv) {
		if (now) {
			Dbg_On(interp,1);
		} else {
			goto usage;
		}
	} else if (0 == strcmp(*argv,"0")) {
		Dbg_Off(interp);
	} else {
		Dbg_On(interp,now);
	}
	return(TCL_OK);
 usage:
	interp->result = "usage: [[-now] 1|0]";
	return TCL_ERROR;
}

int
Dbg_Init(interp)
Tcl_Interp *interp;
{
	Tcl_CreateCommand(interp,Dbg_DefaultCmdName,App_DebugCmd,
			(ClientData)0,(void (*)())0);
	return TCL_OK;	
}

