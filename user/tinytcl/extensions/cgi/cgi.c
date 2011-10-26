/*
 * cgi.c
 *
 * Implements the cgi command
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <tcl.h>
#include <tclInt.h>
#include <tclmod.h>


static char hex2char(const char *hex)
{
	char char_value;
	char_value = (hex[0] >= 'A' ? ((hex[0] & 0xdf) - 'A') + 10 : (hex[0] - '0'));
	char_value *= 16;
	char_value += (hex[1] >= 'A' ? ((hex[1] & 0xdf) - 'A') + 10 : (hex[1] - '0'));
	return char_value;
}

/**
 * Decode a www-url-encoded string in-place
 */
static void decode_url_encoded_string(char *str)
{
	char *dest;

	for (dest = str; *str; str++) {
		if (*str == '+') {
			*dest++ = ' ';
		}
		else if (*str == '%') {
			*dest++ = hex2char(str + 1);

			if (*(dest - 1) == '\r')
				dest--;

			str += 2;
		}
		else {
			*dest++ = *str;
		}
	}
	*dest = 0;
}

static int cgi_cmd_parse(Tcl_Interp *interp, int argc, char **argv)
{
	char *buf = argv[0];
	char *pt;
	static const char *sep = "&;";

	while (*buf) {
		char *value;

		/* Skip leading separators and spaces */
		while (strchr(sep, *buf) || *buf == ' ') {
			buf++;
		}
		if (!*buf) {
			/* Nothing left */
			break;
		}

		/* Find the end of this element */
		pt = buf + strcspn(buf, sep);
		if (*pt) {
			*pt++ = 0;
		}

		/* Find the value */
		value = strchr(buf, '=');
		if (value) {
			*value++ = 0;
		}

		/* Now decode the name and the value in place */
		decode_url_encoded_string(buf);
		if (value) {
			decode_url_encoded_string(value);
		}

		Tcl_AppendElement(interp, buf, 0);
		Tcl_AppendElement(interp, value ?: "", 0);

		if (!*pt) {
			/* No more elements */
			break;
		}
		buf = pt;
	}

	return TCL_OK;
}

/*
 *-----------------------------------------------------------------------------
 *
 * Tcl_CgiCmd --
 *
 *     cgi parse <www-url-encoded-string>
 *
 *         Decodes the string and returns a list of name/value pairs
 *
 * Results:
 *      Standard TCL result.
 *-----------------------------------------------------------------------------
 */

static const tclmod_command_type command_table[] = {
	{	.cmd = "parse",
		.args = "buf",
		.function = cgi_cmd_parse,
		.minargs = 1,
		.maxargs = 1,
		.description = "Parse the given GET or POST buffern www-url-encoded format and return name value pairs"
	},
	{ 0 }
};

static int
Tcl_CgiCmd(ClientData clientData, Tcl_Interp *interp, int argc, char **argv)
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
int cgi_Init(Tcl_Interp *interp)
{
	Tcl_CreateCommand(interp, "cgi", Tcl_CgiCmd, 0, 0);

	return(TCL_OK);
}
