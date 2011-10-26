/*
 * ledman.c
 *
 * Implements the ledman command to access LEDs
 *
 * Copyright (c) 2005 Snapgear
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <linux/ledman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <tcl.h>
#include <tclInt.h>
#include <tclmod.h>

static int do_ledman(Tcl_Interp *interp, const char *cmdname, int cmd, const char *led);

static const char *ledman_leds[LEDMAN_MAX] = {
	"all",
	"power",
	"heartbeat",
	"com1rx",
	"com1tx",
	"com2rx",
	"com2tx",
	"lan1rx",
	"lan1tx",
	"lan2rx",
	"lan2tx",
	"usb1rx",
	"usb1tx",
	"usb2rx",
	"usb2tx",
	"nvram1",
	"nvram2",
	"vpn",
	"lan1dhcp",
	"lan2dhcp",
	"com1dcd",
	"com2dcd",
	"online",
	"lan1link",
	"lan2link",
	"vpnrx",
	"vpntx",
	"reset",
	"static",
	"lan3rx",
	"lan3tx",
	"lan3link",
	"lan3dhcp",
	"failover",
	"highavail"
};

static int ledman_cmd_on(Tcl_Interp *interp, int argc, char **argv)
{
	return do_ledman(interp, "on", LEDMAN_CMD_ON, argv[0]);
}

static int ledman_cmd_off(Tcl_Interp *interp, int argc, char **argv)
{
	return do_ledman(interp, "off", LEDMAN_CMD_OFF, argv[0]);
}

static int ledman_cmd_set(Tcl_Interp *interp, int argc, char **argv)
{
	return do_ledman(interp, "set", LEDMAN_CMD_SET, argv[0]);
}

static int ledman_cmd_flash(Tcl_Interp *interp, int argc, char **argv)
{
	return do_ledman(interp, "flash", LEDMAN_CMD_FLASH, argv[0]);
}

static int ledman_cmd_reset(Tcl_Interp *interp, int argc, char **argv)
{
	return do_ledman(interp, "reset", LEDMAN_CMD_RESET, argv[0]);
}

static int do_ledman(Tcl_Interp *interp, const char *cmdname, int cmd, const char *led)
{
	int i;
	int lednum = -1;

	for (i = 0; i < sizeof(ledman_leds) / sizeof(*ledman_leds); i++) {
		if (strcmp(ledman_leds[i], led) == 0) {
			lednum = i;
			break;
		}
	}

	if (lednum == -1) {
		Tcl_AppendResult(interp, "ledman: Unknown led, ", led, ", use 'ledman leds' for a list of known leds", 0);
		return(TCL_ERROR);
	}

	ledman_cmd(cmd, lednum);

	return TCL_OK;
}

static int ledman_cmd_leds(Tcl_Interp *interp, int argc, char **argv)
{
	int i;

	for (i = 0; i < sizeof(ledman_leds) / sizeof(*ledman_leds); i++) {
		Tcl_AppendElement(interp, ledman_leds[i], 0);
	}

	return TCL_OK;
}

/*
 *-----------------------------------------------------------------------------
 *
 * Tcl_LedmanCmd --
 *
 *     ledman on|off|set|flash|reset <ledname>
 *
 *         Performs the given ledman command on the given led
 *
 *     ledman leds
 *
 *			List the known leds
 *
 * Results:
 *      Standard TCL result.
 *-----------------------------------------------------------------------------
 */

static const tclmod_command_type command_table[] = {
	{	.cmd = "on",
		.args = "led",
		.function = ledman_cmd_on,
		.minargs = 1,
		.maxargs = 1,
		.description = "Turn on the given led"
	},
	{	.cmd = "off",
		.args = "led",
		.function = ledman_cmd_off,
		.minargs = 1,
		.maxargs = 1,
		.description = "Turn off the given led"
	},
	{	.cmd = "set",
		.args = "led",
		.function = ledman_cmd_set,
		.minargs = 1,
		.maxargs = 1,
		.description = "Turn on the given led briefly"
	},
	{	.cmd = "flash",
		.args = "led",
		.function = ledman_cmd_flash,
		.minargs = 1,
		.maxargs = 1,
		.description = "Set the given led to flashing state"
	},
	{	.cmd = "reset",
		.args = "led",
		.function = ledman_cmd_reset,
		.minargs = 1,
		.maxargs = 1,
		.description = "Reset the given led to its default setting"
	},
	{	.cmd = "leds",
		.args = "",
		.function = ledman_cmd_leds,
		.minargs = 0,
		.maxargs = 0,
		.description = "Returns a list of the known led names"
	},
	{ 0 }
};

static int
Tcl_LedmanCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
{
	const tclmod_command_type *ct = tclmod_parse_cmd(interp, command_table, argc, argv);

	if (ct) {
		return ct->function(interp, argc - 2, argv + 2);
	}

	return TCL_ERROR;
}

/**
 * This is the initialisation command for this extension.
 */
int ledman_Init(Tcl_Interp *interp)
{
	Tcl_CreateCommand(interp, "ledman", Tcl_LedmanCmd, 0, 0);

	return(TCL_OK);
}
