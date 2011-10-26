/*
 * printbenv
 *
 * Print requested variables from uCbootloader environment
 * Note that these are handy for use in minix shell script
 * fragments...
 *
 * (c) Michael Leslie <mleslie@arcturusnetworks.com>,
 *     Arcturus Networks Inc. 2002
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/uCbootstrap.h>

/****** data declarations: **************************************************/

char *opt_variable = NULL; /* viariable (if any) to look up */
int   opt_debug    = 0;    /* print debug info here and in uCbootloader */
int   opt_quotes   = 0;    /* enclose variable contents in quotes */
int   opt_printall = 0;    /* print all bootloader environment variables */

int   opt_export   = 0;    /* prepend each var=val pair with "export" */
int   opt_nooids   = 0;    /* filter out oids */
int   opt_onlyoids = 0;    /* print only oids */

#define DBG(a1, a2...) if (opt_debug) fprintf(stderr, a1, ##a2)

/****** function prototypes: ************************************************/

int parse_args(int argc, char *argv[]);
void usage(void);
int print_variable(char *name, char *value);

_bsc1(char *, readbenv, int, a1)
_bsc1(char *, getbenv, char *, a1)


/****** main(): *************************************************************/

int main(int argc, char *argv[]) 
{
	char *varname, *value;

	if (parse_args (argc, argv))
		usage();

/*     if (argc > 1) { */
/* 		if (strcmp(argv[1], "-q") == 0) { */
/* 			opt_quotes = 1; */
/* 			if (argc == 2) */
/* 				opt_prall = 1; */
/* 		} */
/*     } else */
/* 		opt_prall = 1; */


    if (opt_printall) {

		varname = (char *)readbenv(0);
		while (varname != NULL) {
			print_variable (varname, readbenv(2));
			varname = (char *)readbenv(1);
		}

    } else if (opt_variable != NULL) {

		value = (char *)getbenv(opt_variable);
		print_variable (opt_variable, value);

	}

	return(0); 
	}

/****** function declarations: **********************************************/

/*
 * parse_args(int argc, char *argv[])
 *
 * Parse command line arguments and set corresponding
 * opt_xxx variables.
 *
 */
int parse_args(int argc, char *argv[])
{
	char *c;
	int i;

	if (argc == 1) {
		opt_printall = 1;
    return(0); 
}
	

	for (i=1;i<argc;i++) {
		if ((strlen(argv[i]) == 2) &&
			((argv[i][0] == '-') || (argv[i][0] == '+')) 
			) {
			
			switch (argv[i][1]) {
			case 'q': opt_quotes      = 1; break;
			case 'e': opt_export      = 1; break;
			case 'd': opt_debug       = 1; break;

			case 'o':
				if (argv[i][0] == '-')
					opt_nooids = 1; 
				else if (argv[i][0] == '+')
					opt_onlyoids = 1; 
				break;

			default:
				fprintf (stderr,
						 "Unknown option \"%s\" - Aborting.\n\n", argv[i]);
				usage();
				break;
			}
		} else {
			opt_variable = argv[i];
		}
	}

	/* if no options were considered to be variable name arguments
	 * for retrieval, assume we have to print all
	 */
	if (opt_variable == NULL)
		opt_printall = 1;


	/* print out options if debug enabled: */
	DBG("opt_quotes      = %d;\n", opt_quotes);
	DBG("opt_export      = %d;\n", opt_export);
	DBG("opt_debug       = %d;\n", opt_debug);
	DBG("opt_nooids      = %d;\n", opt_nooids);
	DBG("opt_onlyoids    = %d;\n", opt_onlyoids);
	DBG("opt_variable    = %s\n",  opt_variable);
	DBG("opt_printall    = %d\n",  opt_printall);

	return (0);
}

void usage()
{
	fprintf (stderr,
"usage: printbenv [-qed][-o|+o] [variable name]\n"
"\n"
"    \"printbenv\" will print the specified uCbootloader environment\n"
"    variable \"variable name\" in the form: \"VARIABLE=VALUE\".\n"
"\n"
"       -q will enclosethe variable in quotes.\n"
"       -e will prepend the \"export\" keyword for use in shell scripts.\n"
"       -d will print debugging information to stderr.\n"
"       -o will filter out variables whose name is an OID of the form:\n"
"          dd.dd.dd.dd...\n"
"       +o will print *only* OIDs\n"
"\n"
"    If no variable name is specified then all uCbootloader variables\n"
"    are printed.\n"
);

	exit(1);
}



int print_variable(char *name, char *value)
{

	if (!strcmp(value, "(null)"))
		value = "";

	printf("%s=%s%s%s",
		   name, 
		   opt_quotes?"\"":"",
		   value,
		   opt_quotes?"\"":"");

	if (opt_export)
		printf("; export %s\n", name);
	else
		printf("\n");
}



/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
