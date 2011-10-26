/*
  A front end for ld which works in the uClinux build environment

  Based on ucfront which was written by Steve Bennett <steveb@snapgear.com>
  Changes mostly involved deleting code.

  Argument processing code based on ccache

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "ucfront.h"

#define MYNAME "ucfront-ld"

/* the debug logfile name, if set */
char *cache_logfile = NULL;

/* the argument list after processing */
static ARGS *stripped_args;

/* the original argument list */
static ARGS *orig_args;

/* Are we using uClibc or glibc? */
static enum {
	LIBTYPE_NONE,
	LIBTYPE_GLIBC,
	LIBTYPE_UCLIBC,
	LIBTYPE_LIBC,
} libtype = LIBTYPE_NONE;

static int ucfront_debug = 0;

static char *rootdir;
static char *stagedir;
static const char *argv0;
static char *libc_libdir = 0;

#if 0
/* Print the given args */
static void print_args(FILE *fh, ARGS *args)
{
	int i;
	for (i = 0; i < args->argc; i++) {
		if (i != 0) {
			fputc(' ', fh);
		}
		fputs(args->argv[i], fh);
	}
	fputc('\n', fh);
	fflush(fh);
}
#endif

static void log_args(ARGS *args)
{
	int i;
	for (i = 0; i < args->argc; i++) {
		if (i != 0) {
			cc_log(" ");
		}
		cc_log("%s", args->argv[i]);
	}
	cc_log("\n");
}


/*
 * Invoke the linker with the original arguments (minus --ucfront- prefixes)
*/
static void invoke_original_linker(void)
{
	char *e;

	/* strip any local args */
	args_strip(orig_args, "--ucfront-");

	if ((e=getenv("UCFRONT_PREFIX"))) {
		char *p = find_executable(e, MYNAME);
		if (!p) {
			perror(e);
			exit(1);
		}
		args_add_prefix(orig_args, p);
	}
	
	if (ucfront_debug) {
		cc_log("Bypass: ");
		log_args(orig_args);
	}

	execv(orig_args->argv[0], orig_args->argv);
	cc_log("execv returned (%s)!\n", strerror(errno));
	perror(orig_args->argv[0]);
	exit(1);
}

/* find the real linker. We just search the PATH to find a executable of the 
   same name that isn't a link to ourselves */
static void find_linker(int argc, char **argv)
{
	char *base;
	char *path;

	orig_args = args_init(argc, argv);

	base = str_basename(argv[0]);

	/* we might be being invoked like "ucfront-ld ld ..." */
	if (argc > 1 && strncmp(base, MYNAME, sizeof(MYNAME) - 1) == 0) {
		args_remove_first(orig_args);
		free(base);
		if (strchr(argv[1],'/')) {
			/* a full path was given */
			cc_log("Found full path to linker afer removing myname: %s\n", argv[1]);
			return;
		}
		base = str_basename(argv[1]);

		cc_log("Found base linker name afer removing myname: %s\n", base);
	}

	/* support user override of the linker */
	if ((path=getenv("UCFRONT_LD"))) {
		base = strdup(path);

		cc_log("Using explicit UCFRONT_LD=%s linker\n", base);
	}

	orig_args->argv[0] = find_executable(base, MYNAME);

	cc_log("Searching for executable %s gave %s\n", base, orig_args->argv[0]);

	/* can't find the linker! */
	if (!orig_args->argv[0]) {
		perror(base);
		exit(1);
	}
}

/* Search for an executable 'prog' along the given path.
 * Returns the full path to the executable as an allocated string,
 * or 0 if not found.
 *
 * If 'prog' is already an absolute path, just returns it.
 */
const char *find_on_path(const char *prog, const char *path)
{
	char *pathstr;
	char *pt;
	char *next;
	uid_t	uid;
	gid_t	gid;

	if (*prog == '/') {
		return strdup(prog);
	}

	pathstr = strdup(path);
	uid = getuid();
	gid = getgid();

	for (pt = pathstr; pt; pt = next) {
		char *fullpath;
		struct stat st;

		next = strchr(pt, ':');
		if (next) {
			*next++ = 0;
		}

		x_asprintf(&fullpath, "%s/%s", pt, prog);

		if (stat(fullpath, &st) == 0 && ((uid == 0 && (st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))) || 
					    (uid == st.st_uid && (st.st_mode & S_IXUSR)) ||
					    (gid == st.st_gid && (st.st_mode & S_IXGRP)) ||
					    (st.st_mode & S_IXOTH))) {
			/* Found an executable */
			free(pathstr);
			return fullpath;
		}
		free(fullpath);
	}

	free(pathstr);

	return 0;
}

/**
 * Determines the environment in the following ways:
 *
 * 1. If environment variables such as $ROOTDIR, $CONFIG_DEFAULTS_LIBC_UCLIBC and $CONFIG_LIBCDIR
 *    are set, works out libc from there.
 *
 * 2. If $ROOTDIR is set, but not the others, look in $ROOTDIR/.config for settings
 *
 * 3. If $ROOTDIR is not set, look at our path (which we expect to be $ROOTDIR/tools) to
 *    determine ROOTDIR and then proceed as in (2).
 */
static void find_lib_env(void)
{
	char *config_libcdir = getenv("CONFIG_LIBCDIR");

	rootdir = getenv("ROOTDIR");

	if (!rootdir) {
		char *pt;

		rootdir = strdup(argv0);

		pt = strstr(rootdir, "/tools/");
		if (!pt) {
			fatal("Could not determine ROOTDIR from argv[0]=%s\n", argv0);
		}
		*pt = 0;
	}

	stagedir = getenv("STAGEDIR");
	if (!stagedir)
		x_asprintf(&stagedir, "%s/staging", rootdir);

	if (!config_libcdir) {
		/* Not set, so read $ROOTDIR/.config and set the environment */
		char *dot_config;
		FILE *fh;
		char buf[256];

		x_asprintf(&dot_config, "%s/.config", rootdir);

		fh = fopen(dot_config, "r");
		if (!fh) {
			fatal("Failed to open %s\n", dot_config);
		}

		while (fgets(buf, sizeof(buf), fh) != 0) {
			char *pt;

			if (buf[0] == '#') {
				continue;
			}
			pt = strchr(buf, '\n');
			if (pt) {
				*pt = 0;
			}
			if (!buf[0]) {
				continue;
			}
			pt = strchr(buf, '=');
			if (pt) {
				*pt++ = 0;
				setenv(buf, pt, 1);
			}
		}
		fclose(fh);
		config_libcdir = getenv("CONFIG_LIBCDIR");
	}

	if (getenv("CONFIG_DEFAULTS_LIBC_UCLIBC")) {
		if (config_libcdir) {
			libtype = LIBTYPE_UCLIBC;
			x_asprintf(&libc_libdir, "%s/%s/lib", rootdir, config_libcdir);
		}
	}
	else if (getenv("CONFIG_DEFAULTS_LIBC_GLIBC")) {
		if (config_libcdir) {
			libtype = LIBTYPE_GLIBC;
			x_asprintf(&libc_libdir, "%s/%s/build/lib", rootdir, config_libcdir);
		}
	}
	else if (getenv("CONFIG_DEFAULTS_LIBC_UC_LIBC")) {
		if (config_libcdir) {
			libtype = LIBTYPE_LIBC;
			x_asprintf(&libc_libdir, "%s/lib/%s", rootdir, config_libcdir);
		}
	}
	else if (getenv("CONFIG_DEFAULTS_LIBC_NONE")) {
		libtype = LIBTYPE_NONE;
	}
	else {
		fatal("Could not determine libc. Are $CONFIG_DEFAULTS_LIBC_... and $CONFIG_LIBCDIR set correctly?"); 
	}
}

/**
 * Process the linker options, to determine what mode
 * we were called in and insert extra arguments as necessary.
 */
static void process_args(int argc, char **argv)
{
	int i;
	char *e;
	const char *linker = argv[0];
	int nostdlib = 0;

	find_lib_env();

	stripped_args = args_init(0, NULL);

	for (i=1; i<argc; i++) {
		if (strcmp(argv[i], "-nostdlib") == 0) {
			nostdlib = 1;
			args_add(stripped_args, argv[i]);
			continue;
		}

		/* The user knows best: just swallow the next arg */
		if (strcmp(argv[i], "--ucfront-skip") == 0) {
			i++;
			if (i == argc) {
				invoke_original_linker();
			}
			args_add(stripped_args, argv[i]);
			continue;
		}

		args_add(stripped_args, argv[i]);
	}

	if (!nostdlib) {
		args_add(stripped_args, "-nostdlib");

		if(libc_libdir) {
			args_add(stripped_args, "-L");
			args_add(stripped_args, libc_libdir);
		}

		x_asprintf(&e, "%s/lib", stagedir);
		args_add(stripped_args, "-L");
		args_add(stripped_args, e);
	}

	/* Now add the linker */
	args_add_prefix(stripped_args, linker);

	/* Add any specified prefix */
	if ((e=getenv("UCFRONT_PREFIX"))) {
		char *p = find_executable(e, MYNAME);
		if (!p) {
			perror(e);
			exit(1);
		}
		args_add_prefix(stripped_args, p);
	}
}

/* the main ucfront driver function */
static void ucfront(int argc, char *argv[])
{
	const char *pt = getenv("UCFRONT_DEBUG");
	if (pt) {
		ucfront_debug = atoi(getenv("UCFRONT_DEBUG"));
		if (!ucfront_debug) {
			ucfront_debug = 1;
		}
	}

	/* find the real compiler */
	find_linker(argc, argv);

	if (ucfront_debug) {
		cc_log("Original: ");
		log_args(orig_args);
	}

	if (getenv("UCFRONT_DISABLE")) {
		invoke_original_linker();
	}
	
	/* process argument list, returning a new set of arguments for pre-processing */
	process_args(orig_args->argc, orig_args->argv);

	/* Print the args for debugging */
	if (ucfront_debug) {
		cc_log("Final: ");
		log_args(stripped_args);
		/* Don't log this to stderr since it can confuse configure */
		/*print_args(stderr, stripped_args);*/
	}

	/* Now execute the actual command */
	execv(stripped_args->argv[0], stripped_args->argv);

	perror("execv");

	exit(1);
}


static void usage(void)
{
	printf("ucfront, a uClinux linker front end. Version %s\n", UCFRONT_VERSION);
	
	printf("Usage:\n");
	printf("\tucfront-ld [options]\n");
	printf("\tucfront<anything> linker [link options]\n");
	printf("\tlinker [link options]    (via symbolic link)\n");
	printf("\nOptions:\n");

	printf("-h                      this help page\n");
	printf("-V                      print version number\n");
}

/* the main program when not doing a compile */
static int ucfront_main(int argc, char *argv[])
{
	extern int optind;
	int c;

	while ((c = getopt(argc, argv, "Vh")) != -1) {
		switch (c) {
		case 'V':
			printf("ucfront-ld version %s\n", UCFRONT_VERSION);
			printf("Released under the GNU GPL v2 or later\n");
			exit(0);

		case 'h':
			usage();
			exit(0);
			
		default:
			usage();
			exit(1);
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	cache_logfile = getenv("UCFRONT_LOGFILE");

	/* Try to find this executable on the path */
	argv0 = find_on_path(argv[0], getenv("PATH") ?: "") ?: argv[0];

	/* check if we are being invoked as "ucfront" */
	if (strlen(argv[0]) >= strlen(MYNAME) &&
	    strcmp(argv[0] + strlen(argv[0]) - strlen(MYNAME), MYNAME) == 0) {
		if (argc < 2) {
			usage();
			exit(1);
		}
		/* if the first argument isn't an option, then assume we are
		   being passed a compiler name and options */
		if (argv[1][0] == '-') {
			return ucfront_main(argc, argv);
		}
	}

	ucfront(argc, argv);
	return 1;
}
