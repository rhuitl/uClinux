#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdarg.h>

#define _GNU_SOURCE
#include <getopt.h>

#define MY_VERSION "0.22"


struct library {
	const char *name;
	const char *version;
	const char *Largs;
	const char *largs;
	const char *Iargs;
};

#define LIB(n, ver, l)	{ n, ver, NULL, l, NULL }
static const struct library all_libs[] = {
	LIB("libxml-2.0", "2.7.2", "-lxml"),
};
#define N_LIBS	(sizeof(all_libs) / sizeof(struct library))


enum {
	OPT_USAGE=300,
	OPT_ATLEAST_PKGCONFIG_VERSION,
	OPT_CFLAGS,
	OPT_ERRORS_TO_STDOUT,
	OPT_EXISTS,
	OPT_LIBS,
	OPT_LIBS_ONLY_L,
	OPT_LIBS_ONLY_l,
	OPT_PRINT_ERRORS,
	OPT_SHORT_ERRORS,
	OPT_VERSION,
#if 0
	OPT_SILENCE_ERRORS,
	OPT_UNINSTALLED,
	OPT_ATLEAST_VERSION,
	OPT_EXACT_VERSION,
	OPT_MAX_VERSION,
	OPT_STATIC,
#endif
};

static const struct option opts[] = {
	{ "help", 0, 0, '?' },		// These two must be first
	{ "usage", 0, 0, OPT_USAGE },

	{ "atleast-pkgconfig-version", 1, 0, OPT_ATLEAST_PKGCONFIG_VERSION },
	{ "cflags", 0, 0, OPT_CFLAGS },
	{ "errors-to-stdout", 0, 0, OPT_ERRORS_TO_STDOUT },
	{ "exists", 0, 0, OPT_EXISTS },
	{ "libs", 0, 0, OPT_LIBS },
	{ "libs-only-L", 0, 0, OPT_LIBS_ONLY_L },
	{ "libs-only-l", 0, 0, OPT_LIBS_ONLY_l },
	{ "print-errors", 0, 0, OPT_PRINT_ERRORS },
	{ "short-errors", 0, 0, OPT_SHORT_ERRORS },
	{ "version", 0, 0, OPT_VERSION },
#if 0
	{ "modversion", 0, 0, OPT_MODVERSION },
	{ "silence-errors", 0, 0, OPT_SILENCE_ERRORS },
	{ "uninstalled", 0, 0, OPT_UNINSTALLED },
	{ "atleast-version", 1, 0, OPT_ATLEAST_VERSION },
	{ "exact-version", 1, 0, OPT_EXACT_VERSION },
	{ "max-version", 1, 0, OPT_MAX_VERSION },
	{ "static", 0, 0, OPT_STATIC },
#endif
	{ 0, 0, 0, 0 }
};

static const char *min_cfg_ver = NULL;
static unsigned char cflags, exists, libs, l_args, L_args;
static unsigned char error_stdout, print_errors, short_errors;

extern void debug(const char *, ...) __attribute__ ((format(printf, 1, 2)));
static void msg(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	if (error_stdout)
		vprintf(fmt, ap);
	else
		vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void usage(const char *pname) {
	int i;

	msg("Usage: %s [OPTION...]\n", pname);
	for (i=2; opts[i].name != 0; i++)
		msg("  %s\n", opts[i].name);
	msg("\nHelp options\n");
	msg("  -?, --help\n");
	msg("  --usage\n");
}

static void usage_hint(const char *pname) {
	int i;
	int nl = 1;

	msg("Usage: %s [-?]", pname);
	for (i=0; opts[i].name != 0; i++) {
		msg(" [%s", opts[i].name);
		if (opts[i].has_arg)
			msg("=ARG");
		msg("]");
		if ((i % 3) == 2) {
			msg("\n");
			nl = 0;
		} else
			nl = 1;
	}
	if (nl)
		msg("\n");
}


/* Routine to compare version strings
 */
static int compare_versions(char *have, char *want) {
	int v1, v2;

	while (want != NULL && *want != '\0') {
		if (*have != '\0')
			v1 = strtol(have, &have, 10);
		else	v1 = 0;

		v2 = strtol(want, &want, 10);
		if (v1 > v2)
			return 0;
		if (v1 < v2)
			return -1;

		while (*have == '.') have++;
		while (*want == '.') want++;
	}
	return 0;
}


/* Routines to check out version against the desired version.
 * Return if we're greater of equal versions, exit with an error
 * if not.
 */
static void check_version(char *want) {
	if (compare_versions(MY_VERSION, want))
		exit(1);
}

static void process_args(int argc, char *argv[]) {
	int c;
	int opt_idx = 0;

	while ((c = getopt_long(argc, argv, "?", opts, &opt_idx)) != -1) {
		switch (c) {
		case OPT_CFLAGS:		cflags = 1;		break;
		case OPT_ERRORS_TO_STDOUT:	error_stdout = 1;	break;
		case OPT_EXISTS:		exists = 1;		break;
		case OPT_LIBS:			libs = 1;		break;
		case OPT_LIBS_ONLY_L:		L_args = 1;		break;
		case OPT_LIBS_ONLY_l:		l_args = 1;		break;

		case OPT_PRINT_ERRORS:		print_errors = 1;	break;
		case OPT_SHORT_ERRORS:		short_errors = 1;	break;

		case OPT_ATLEAST_PKGCONFIG_VERSION:
			check_version(optarg);
			break;
		case OPT_VERSION:
			puts(MY_VERSION);
			exit(0);
		case OPT_USAGE:
			usage_hint(argv[0]);
			exit(0);
		case '?':
			usage(argv[0]);
			exit(0);
		default:
			usage(argv[0]);
			exit(1);
		}
	}
}


/* Found the required libary.
 * produce whatever output is required.
 */
static void output_lib(const struct library *l) {
	if (cflags)
		if (l->Iargs != NULL)
			printf("%s ", l->Iargs);
	if (libs || L_args)
		if (l->Largs != NULL)
			printf("%s ", l->Largs);
	if (libs || l_args)
		if (l->largs != NULL)
			printf("%s ", l->largs);
}

/* Search for the library specified and do what is required with it.
 */
static void process_library(const char *lib) {
	int i;

	for (i=0; i<N_LIBS; i++)
		if (strcmp(lib, all_libs[i].name) == 0)
			break;
	if (i == N_LIBS) {
		if (print_errors) {
			if (short_errors)
				msg("No package '%s' found\n", lib);
			else
				msg("Package %s was not found in the pkg-config search path.\n"
					"Perhaps you should add the directory containing `%s.pc'\n"
					"to the PKG_CONFIG_PATH environment variable\n"
					"No package '%s' found\n", lib, lib, lib);
		}
		exit(1);
	}

	output_lib(all_libs + i);
}


int main(int argc, char *argv[]) {
	process_args(argc, argv);

	while (optind < argc)
		process_library(argv[optind++]);
	return 0;
}
