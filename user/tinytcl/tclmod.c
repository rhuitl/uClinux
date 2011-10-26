/*
 * tclmod.c
 *
 *
 * Copyright (c) 2005 Snapgear
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 */
#include <string.h>

#include "tclmod.h"

int tcl_split_one_arg(Tcl_Interp *interp, int *argc, char ***argv)
{
	if (*argc == 1 && strchr((*argv)[0], ' ') != 0) {
		if (Tcl_SplitList(interp, (*argv)[0], argc, argv) == TCL_OK) {
			return(1);
		}
	}
	return(0);
}

/**
 * Implements the common 'commands' subcommand
 */
static int tclmod_cmd_commands(Tcl_Interp *interp, int argc, char **argv)
{
	/* Nothing to do, since the result has already been created */
	return(TCL_OK);
}

/**
 * Builtin command.
 */
static const tclmod_command_type tclmod_command_entry = {
	.cmd = "commands",
	.minargs = 0,
	.maxargs = 0,
	.function = tclmod_cmd_commands,
	.flags = TCL_MODFLAG_HIDDEN | TCL_MODFLAG_BUILTIN,
	.description =	"Returns a list of supported commands",
};

/**
 * Returns 0 if no match.
 * Returns 1 if match and args OK.
 * Returns -1 if match but args not OK (leaves error in interp->result)
 */
static int check_match_command(Tcl_Interp *interp, const tclmod_command_type *ct, int argc, char *argv[])
{
	if (strcmp(ct->cmd, argv[1]) == 0) {
		if (argc == 3 && strcmp(argv[2], "?") == 0) {
			Tcl_AppendResult (interp, "Usage: ", argv[0], " ", ct->cmd, " ", ct->args, "\n\n", ct->description, (char *) NULL);
			return -1;
		}
		if (argc < ct->minargs + 2 || (ct->maxargs >= 0 && argc > ct->maxargs + 2)) {
			Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0], " ", ct->cmd, " ", ct->args, "\"", (char *) NULL);
			return -1;
		}

		return 1;
	}
	return 0;
}

const tclmod_command_type *
tclmod_parse_cmd(Tcl_Interp *interp, const tclmod_command_type *command_table, int argc, char **argv)
{
	const tclmod_command_type *ct;
	const char *sep;
	int ret;

	if (argc < 2) {
		Tcl_AppendResult (interp, "wrong # args: should be \"", argv[0], " command ...\"\n", (char *) NULL);
		Tcl_AppendResult (interp, "Use \"", argv[0], " ?\" or \"", argv[0], " command ?\" for help", (char *) NULL);
		return 0;
	}

	for (ct = command_table; ct->cmd; ct++) {
		ret = check_match_command(interp, ct, argc, argv);
		if (ret == 1) {
			/* Matched and args OK */
			return ct;
		}
		if (ret == -1) {
			/* Matched, but bad args */
			return 0;
		}
	}

	/* No match, so see if it is a builtin command */
	if (strcmp(argv[1], "commands") == 0) {
		const tclmod_command_type *ct;

		for (ct = command_table; ct->cmd; ct++) {
			if (!(ct->flags & TCL_MODFLAG_HIDDEN)) {
				Tcl_AppendElement(interp, (char *)ct->cmd, 0);
			}
		}
		return &tclmod_command_entry;
	}

	/* No, so show usage */
	if (strcmp(argv[1], "?") == 0) {
		Tcl_AppendResult(interp, "Usage: \"", argv[0], " command ...\", where command is one of: ", (char *) NULL);
	}
	else {
		Tcl_AppendResult(interp, "Error: ", argv[0], ", unknown command \"", argv[1], "\": should be ", (char *) NULL);
	}

	sep = "";
	for (ct = command_table; ct->cmd; ct++) {
		if (!(ct->flags & TCL_MODFLAG_HIDDEN)) {
			Tcl_AppendResult(interp, sep, ct->cmd, (char *) NULL);
			sep = ", ";
		}
	}
	return 0;
}
