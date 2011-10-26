/*
 * tclmod.h
 *
 *
 * Provides a common approach to implementing Tcl commands
 * which implement subcommands
 *
 * Copyright (c) 2005 Snapgear
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 */
#ifndef TCLMOD_H
#define TCLMOD_H

#include <tcl.h>

#define TCL_MODFLAG_HIDDEN  0x0001
#define TCL_MODFLAG_BUILTIN 0x0002
/* Custom flags start at 0x0100 */

typedef int tclmod_cmd_function(Tcl_Interp *interp, int argc, char **argv);

typedef struct {
	const char *cmd;				/* Name of the (sub)command */
	const char *args;				/* Textual description of allowed args */
	tclmod_cmd_function *function;		/* Function implementing the subcommand */
	short minargs;					/* Minimum required arguments */
	short maxargs;					/* Maximum allowed arguments or -1 if no limit */
	unsigned flags;					/* TCL_MODFLAG_... plus custom flags */
	const char *description;		/* Description of the subcommand */
} tclmod_command_type;

/**
 * Often a command may be called with either multiple arguments, or
 * a single argument which is a list.
 * This function detects a single argument which is a list and splits that
 * list into separate arguments and updates *argc and *argv appropriately.
 *
 * Returns 1 if the list was split (in which case *argv will need to be freed)
 * or 0 if no changes were made.
 */
int tcl_split_one_arg(Tcl_Interp *interp, int *argc, char ***argv);

/**
 * Looks up the appropriate subcommand in the given command table and return
 * the command function which implements the subcommand.
 * 0 will be returned and an appropriate error will be set if the subcommand or 
 * arguments are invalid.
 *
 * Typical usage is:
 *  {
 *    const tclmod_command_type *ct = tclmod_parse_cmd(interp, command_table, argc, argv);
 *
 *    if (ct) {
 *      return ct->function(interp, argc - 2, argv + 2);
 *    }
 *
 *    return TCL_ERROR;
 *  }
 */
const tclmod_command_type *
tclmod_parse_cmd(Tcl_Interp *interp, const tclmod_command_type *command_table, int argc, char **argv);

#endif
