/*
  A front end for gcc which can work with a custom uClibc or glibc library

  Steve Bennett <steveb@snapgear.com>

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

#define MYNAME "ucfront"

/* the debug logfile name, if set */
char *cache_logfile = NULL;

/* the argument list after processing */
static ARGS *stripped_args;

/* contains just some basic args needed when running -print-file-name
 * such as -mbig-endian
 */
static ARGS *basic_args;

/* the original argument list */
static ARGS *orig_args;

/* Are we in link mode? */
static enum {
	MODE_COMPILE,
	MODE_LINK,
	MODE_LINK_SHARED,
	MODE_DEPEND,
} mode = MODE_LINK;

/* Are we using uClibc or glibc? */
static enum {
	LIBTYPE_NONE,
	LIBTYPE_GLIBC,
	LIBTYPE_UCLIBC,
	LIBTYPE_LIBC,
} libtype = LIBTYPE_NONE;

/* Are we generating a flat executable file, if we are do not ever use
 * crtbegin.o/crtend.o as the flat handling does contructors for us
 */
static int flat_executable = 0;

static int cplusplus = 0;

static int ucfront_debug = 0;

static const char *libpaths[100];
static int num_lib_paths = 0;

static struct {
	const char *old;
	const char *new;
} map_dirs[100];
static int num_map_dirs = 0;

static char *rootdir;
static char *stagedir;
static const char *argv0;
static char *libc_libdir = 0;
static char *libc_incdir = 0;

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
 * Invoke the compiler with the original arguments (minus --ucfront- prefixes)
*/
static void invoke_original_compiler(void)
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

/* find the real compiler. We just search the PATH to find a executable of the 
   same name that isn't a link to ourselves */
static void find_compiler(int argc, char **argv)
{
	char *base;
	char *path;

	orig_args = args_init(argc, argv);

	base = str_basename(argv[0]);

	/* we might be being invoked like "ucfront gcc -c foo.c" or "ucfront-gcc gcc ..." */
	if (argc > 1 && strncmp(base, MYNAME, sizeof(MYNAME) - 1) == 0) {
		args_remove_first(orig_args);
		free(base);
		if (strchr(argv[1],'/')) {
			/* a full path was given */
			cc_log("Found full path to compiler afer removing myname: %s\n", argv[1]);
			return;
		}
		base = str_basename(argv[1]);

		cc_log("Found base compiler name afer removing myname: %s\n", base);
	}

	/* support user override of the compiler */
	if ((path=getenv("UCFRONT_CC"))) {
		base = strdup(path);

		cc_log("Using explicit UCFRONT_CC=%s compiler\n", base);
	}

	orig_args->argv[0] = find_executable(base, MYNAME);

	cc_log("Searching for executable %s gave %s\n", base, orig_args->argv[0]);

	/* can't find the compiler! */
	if (!orig_args->argv[0]) {
		perror(base);
		exit(1);
	}
}

/**
 * Uses the 'gcc -print-file-name=<filename>' syntax to find
 * the path of the given compiler-supplied file.
 * Adds in the basic_args in case it contains things like -mbig-endian
 */
static char *find_gcc_file(const char *path, const char *filename)
{
	pid_t pid;
	int status;
	char buf[256];
	int ret;
	char *pt;

	int fds[2];

	if (pipe(fds) < 0) {
		fatal("Failed to create pipe");
	}

	pid = fork();
	if (pid == -1) {
		fatal("Failed to fork");
	}
	
	if (pid == 0) {
		char *arg;

		args_add_prefix(basic_args, path);

		x_asprintf(&arg, "-print-file-name=%s", filename);
		args_add(basic_args, arg);

		close(fds[0]);
		dup2(fds[1], 1);
		close(fds[1]);

		exit(execv(path, basic_args->argv));
	}

	close(fds[1]);

	if (waitpid(pid, &status, 0) != pid) {
		fatal("waitpid failed");
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fatal("gcc -print-file-name failed");
	}

	ret = read(fds[0], buf, sizeof(buf) - 1);
	close(fds[0]);

	if (ret <= 0) {
		fatal("gcc -print-file-name=%s failed to return a result", filename);
	}

	buf[ret] = 0;

	pt = strchr(buf, '\n');
	if (pt) {
		*pt = 0;
	}

	if (buf[0] != '/' && strcmp(buf, filename) == 0)
		return NULL;

	return strdup(buf);
}


static void parse_map_dirs(const char *mapping)
{
	const char *cp, *ep;
	int n;

	if (!mapping)
		return;

	cp = mapping;
	while (*cp) {
		/* skip whitespace */
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		/* dir=newdir */
		ep = strchr(cp, '=');
		if (!ep)
			break;
		n = strcspn(ep+1, " \t");
		map_dirs[num_map_dirs].old = strndup(cp, ep - cp);
		map_dirs[num_map_dirs].new = strndup(ep+1, n);
		num_map_dirs++;
		cp = ep + (1 + n);
	}
}

/**
 * 'lib' is something like -labc
 * 
 */
static void add_shared_lib(ARGS *args, const char *lib)
{
	struct stat st;
	char *e;
	int j;

	/* Special flat mode shared library. Need to add something like
	 * -Wl,-R,<libpath>lib<name>.gdb
	 * if we find that the file exists
	 */

	/* Look for this lib along the lib path */
	for (j = 0; j < num_lib_paths; j++) {
		x_asprintf(&e, "%s/lib%s.gdb", libpaths[j], lib + 2);

		if (stat(e, &st) == 0 && S_ISREG(st.st_mode)) {
			/* Found this lib */
			free(e);
			x_asprintf(&e, "-Wl,-R,%s/lib%s.gdb", libpaths[j], lib + 2);
			args_add(args, e);
			break;
		}
	}
	args_add(args, lib);
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

	rootdir = getenv("FAKE_ROOTDIR");
	if (!rootdir)
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
			x_asprintf(&libc_incdir, "%s/%s/include", rootdir, config_libcdir);
		}
	}
	else if (getenv("CONFIG_DEFAULTS_LIBC_GLIBC")) {
		if (config_libcdir) {
			libtype = LIBTYPE_GLIBC;
			x_asprintf(&libc_libdir, "%s/%s/install/lib", rootdir, config_libcdir);
			x_asprintf(&libc_incdir, "%s/%s/install/include", rootdir, config_libcdir);
		}
	}
	else if (getenv("CONFIG_DEFAULTS_LIBC_UC_LIBC")) {
		if (config_libcdir) {
			libtype = LIBTYPE_LIBC;
			x_asprintf(&libc_libdir, "%s/lib/%s", rootdir, config_libcdir);
			x_asprintf(&libc_incdir, "%s/lib/%s/include", rootdir, config_libcdir);
		}
	}
	else if (getenv("CONFIG_DEFAULTS_LIBC_NONE")) {
		if (config_libcdir) {
			libtype = LIBTYPE_NONE;
			libc_libdir = 0;
			libc_incdir = 0;
		}
	}
	else {
		fatal("Could not determine libc. Are $CONFIG_DEFAULTS_LIBC_... and $CONFIG_LIBCDIR set correctly?"); 
	}
}

/**
 * Process the compiler options, to determine what mode
 * we were called in and insert extra arguments as necessary.
 *
 * For compiling: add -nostdinc and -isystem <uclibc-include-dir>
 * For linking: add -nostartfiles -nostdlib as well as the appropriate start files
 *              along with -lc and -lgcc
 *              Note that we detect whether linking a shared library and choose different
 *              start files.
 */
static void process_args(int argc, char **argv)
{
	static const char *opts[] = {
				  "-iprefix", "-imacros",
				  "-iwithprefix", "-iwithprefixbefore",
				  "-D", "-U", "-x", "-MF", 
				  "-MT", "-MQ", "-aux-info",
				  "--param", "-A", "-Xlinker", "-u",
				  "-x",
				  NULL};
	static const char *includes[] = {
				  "-I", "-include",
				  "-isystem", "-idirafter",
				  NULL};

	int i;
	int j;
	int k;
	int input_files = 0;
	struct stat st;
	char *e;
	const char *compiler = argv[0];
	int nostartfiles = 0;
	int nostdinc = 0;
	int nodefaultlibs = 0;
	int id_shared_library = 0;

	find_lib_env();

	stripped_args = args_init(0, NULL);
	basic_args = args_init(0, NULL);

	for (i=1; i<argc; i++) {
		/* we must have -c or -S or -E */
		if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "-E") == 0) {
			args_add(stripped_args, argv[i]);
			mode = MODE_COMPILE;
			continue;
		}

		/* -shared changes the mode */
		if (strcmp(argv[i], "-shared") == 0) {
			args_add(stripped_args, argv[i]);
			mode = MODE_LINK_SHARED;
			continue;
		}

		if (strcmp(argv[i], "-nostartfiles") == 0) {
			nostartfiles = 1;
			continue;
		}

		if (strcmp(argv[i], "-nodefaultlibs") == 0) {
			nodefaultlibs = 1;
			continue;
		}

		if (strcmp(argv[i], "-nostdlib") == 0) {
			nodefaultlibs = 1;
			nostartfiles = 1;
			continue;
		}

		if (strcmp(argv[i], "-nostdinc") == 0) {
			nostdinc = 1;
			continue;
		}

		if (strcmp(argv[i], "-mid-shared-library") == 0) {
			args_add(stripped_args, argv[i]);
			id_shared_library = 1;
			continue;
		}

		/* Need to remember lib paths */
		if (strncmp(argv[i], "-L", 2) == 0) {
			if (strcmp(argv[i], "-L") == 0) {
				if (i == argc-1) {
					fatal("missing argument to -L\n");
				}
				e = argv[++i];
			}
			else {
				e = argv[i] + 2;
			}
			for (k = 0; k < num_map_dirs; k++)
				if (strncmp(map_dirs[k].old, e, strlen(map_dirs[k].old)) == 0) {
					char *newval;
					x_asprintf(&newval, "%s%s",
						map_dirs[k].new, &e[strlen(map_dirs[k].old)]);
					e = newval;
					break;
				}
			libpaths[num_lib_paths++] = e;
			args_add(stripped_args, "-L");
			args_add(stripped_args, e);
			continue;
		}

		/* The user knows best: just swallow the next arg */
		if (strcmp(argv[i], "--ucfront-skip") == 0) {
			i++;
			if (i == argc) {
				invoke_original_compiler();
			}
			args_add(stripped_args, argv[i]);
			continue;
		}

		/* include processing */
		for (j=0;includes[j];j++) {
			if (strcmp(argv[i], includes[j]) == 0) {
				if (i == argc-1) {
					fatal("missing argument to %s\n", includes[j]);
				}
				e = argv[++i];
			} else if (strncmp(argv[i],includes[j],strlen(includes[j])) == 0) {
				e = argv[i] + strlen(includes[j]);
			} else {
				continue;
			}
			for (k = 0; k < num_map_dirs; k++)
				if (strncmp(map_dirs[k].old, e, strlen(map_dirs[k].old)) == 0) {
					char *newval;
					x_asprintf(&newval, "%s%s",
						map_dirs[k].new, &e[strlen(map_dirs[k].old)]);
					e = newval;
					break;
				}
			args_add(stripped_args, includes[j]);
			args_add(stripped_args, e);
			break;
		}
		if (includes[j]) {
			continue;
		}

		/* options that take an argument */
		for (j=0;opts[j];j++) {
			if (strcmp(argv[i], opts[j]) == 0) {
				if (i == argc-1) {
					fatal("missing argument to %s\n", argv[i]);
				}
					
				args_add(stripped_args, argv[i]);
				args_add(stripped_args, argv[i+1]);
				i++;
				break;
			}
		}
		if (opts[j]) {
			continue;
		}

		if (strncmp(argv[i], "-M", 2) == 0) {
			/* These are for dependency generation. */
			args_add(stripped_args, argv[i]);
			mode = MODE_DEPEND;
			continue;
		}

		if (strncmp(argv[i], "-m", 2) == 0) {
			args_add(stripped_args, argv[i]);
			/* Remember this arg in case we do -print-file-name */
			args_add(basic_args, argv[i]);
			continue;
		}

		if (id_shared_library && strncmp(argv[i], "-l", 2) == 0) {
			add_shared_lib(stripped_args, argv[i]);
			continue;
		}

		if (strstr(argv[i], "-elf2flt")) {
			flat_executable = 1;
			args_add(stripped_args, argv[i]);
			continue;
		}
			
		/* other options */
		if (argv[i][0] == '-') {
			args_add(stripped_args, argv[i]);
			continue;
		}

		/* if an argument isn't a plain file then assume its
		   an option, not an input file. This allows us to
		   cope better with unusual compiler options */
		if (stat(argv[i], &st) != 0 || !S_ISREG(st.st_mode)) {
			args_add(stripped_args, argv[i]);
			continue;			
		}

		/* Not an option, so this as an input file */
		args_add(stripped_args, argv[i]);
		input_files++;
	}

	if (mode != MODE_DEPEND && !input_files) {
		cc_log("No input files found\n");
		invoke_original_compiler();
	}

	if (mode == MODE_COMPILE) {
		cc_log("Found -c or -S option, so assuming compile mode\n");
	}
	else if (mode == MODE_DEPEND) {
		cc_log("Found -M option, so assuming dependency mode\n");
	}
	else {
		char *startfile;
		char *rpath;

		if (mode == MODE_LINK) {
			cc_log("Assuming link mode\n");
		}
		else {
			cc_log("Found -shared option, so assuming shared lib link mode\n");
		}

		if (!nostartfiles || !nodefaultlibs) {
			if (libc_libdir && (stat(libc_libdir, &st) != 0 || !S_ISDIR(st.st_mode))) {
				fatal("ucfront: libc lib directory does not exist, %s", libc_libdir);
			}
		}

		/* Now we need to work out where the compilers lib directory is, because we
		 * still need some "standard" start files
		 */
		if (libtype == LIBTYPE_NONE) {
		}
		else if (libtype == LIBTYPE_LIBC) {
			/* This one always uses the compiler start files */
			if (nostartfiles) {
				/*args_add(stripped_args, "XX -nostartfiles XX");*/
			}
			if (nodefaultlibs) {
				args_add(stripped_args, "-nodefaultlibs");
			}
		}
		else {
			if (!nostartfiles) {
				startfile = NULL;
				if (!flat_executable)
					startfile = find_gcc_file(compiler,
							(mode == MODE_LINK) ? "crtbegin.o" : "crtbeginS.o");
				if (startfile)
					args_add_prefix(stripped_args, startfile);
				x_asprintf(&startfile, "%s/crti.o", libc_libdir);
				args_add_prefix(stripped_args, startfile);
				if (mode == MODE_LINK) {
					x_asprintf(&startfile, "%s/crt1.o", libc_libdir);
					args_add_prefix(stripped_args, startfile);
				}
			}

			/* Don't use standard libs or start files */
			args_add_prefix(stripped_args, "-nostdlib");
		}

		if (libtype != LIBTYPE_NONE && !nodefaultlibs) {
			args_add(stripped_args, "-L");
			args_add(stripped_args, libc_libdir);

			x_asprintf(&rpath, "-Wl,-rpath-link,%s", libc_libdir);
			args_add(stripped_args, rpath);

			libpaths[num_lib_paths++] = libc_libdir;
		}

		/* Need to be able to find all the libs */
		x_asprintf(&e, "%s/lib", stagedir);
		args_add(stripped_args, "-L");
		args_add(stripped_args, e);

		x_asprintf(&rpath, "-Wl,-rpath-link,%s", e);
		args_add(stripped_args, rpath);

		libpaths[num_lib_paths++] = e;

		if (!nodefaultlibs) {
			if (id_shared_library) {
				add_shared_lib(stripped_args, "-lc");
				add_shared_lib(stripped_args, "-lgcc");
			}
			else {
				/*
				 * ensure cross references are fixed
				 */
				if (cplusplus) {
					args_add_with_spaces(stripped_args, getenv("SLIBSTDCPP") ?: "-lstdc++");
					args_add_with_spaces(stripped_args, getenv("CXXSUP") ?: "-lsupc++");
				}
				args_add(stripped_args, "-Wl,--start-group");
				if (cplusplus && getenv("CONFIG_LIB_STLPORT")) {
					args_add(stripped_args, "-lpthread");
					args_add(stripped_args, "-lm");
				}
				args_add(stripped_args, "-lc");
				args_add(stripped_args, "-lgcc");
				args_add(stripped_args, "-Wl,--end-group");
			}
		}

		if (!nostartfiles && libtype != LIBTYPE_LIBC && libtype != LIBTYPE_NONE) {
#if 0
			if (libtype == LIBTYPE_GLIBC) {
				x_asprintf(&startfile, "%s/ld-linux.so.2", libc_libdir);
				args_add(stripped_args, startfile);
			}
#endif
			startfile = NULL;
			if (!flat_executable)
				startfile = find_gcc_file(compiler,
						(mode == MODE_LINK) ? "crtend.o" : "crtendS.o");
			if (startfile)
				args_add(stripped_args, startfile);
			x_asprintf(&startfile, "%s/crtn.o", libc_libdir);
			args_add(stripped_args, startfile);
		}

		/*sh-linux-gcc -m4 -ml crt1.o crti.o <orig>/crtbegin.o -o discard discard.o <orig>/crtend.o crtn.o*/
	}

	if (!nostdinc && libtype != LIBTYPE_NONE) {
		char *includedir;

		/* Note that we ALWAYS add -isystem since we may be operating in combined compile/link mode */
		if (stat(libc_incdir, &st) != 0 || !S_ISDIR(st.st_mode)) {
			fprintf(stderr, "ucfront: libc include directory does not exist, %s\n", libc_incdir);
			exit(1);
		}

		/* Do this in reverse order. We use -idirafter so that user-specified include paths come first */
		includedir = find_gcc_file(compiler, "include");
		if (includedir) {
			args_add_prefix(stripped_args, includedir);
			args_add_prefix(stripped_args, "-isystem");
		}

		includedir = find_gcc_file(compiler, "include-fixed");
		if (includedir) {
			args_add_prefix(stripped_args, includedir);
			args_add_prefix(stripped_args, "-isystem");
		}

		args_add_prefix(stripped_args, libc_incdir);
		args_add_prefix(stripped_args, "-isystem");
	}

	if (cplusplus) {
		if (getenv("CONFIG_LIB_STLPORT")) {
			x_asprintf(&e, "%s/include/c++", stagedir);
			args_add_prefix(stripped_args, e);
			args_add_prefix(stripped_args, "-idirafter");
			x_asprintf(&e, "%s", getenv("STL_INCDIR"));
			args_add_prefix(stripped_args, e);
			args_add_prefix(stripped_args, "-idirafter");
		}
		else if (getenv("CONFIG_LIB_UCLIBCXX") ||
				getenv("CONFIG_LIB_UCLIBCXX_FORCE")) {
			x_asprintf(&e, "-I%s/lib/uClibc++/include", stagedir);
			args_add_prefix(stripped_args, e);
		}
		else {
			x_asprintf(&e, "-I%s/include/c++", stagedir);
			args_add_prefix(stripped_args, e);
		}
	}

	/* Do this in reverse order. We use -idirafter so that user-specified include paths come first */
	x_asprintf(&e, "%s/include", stagedir);
	args_add_prefix(stripped_args, e);
	args_add_prefix(stripped_args, "-idirafter");

	if (libtype != LIBTYPE_NONE) {
		/* Don't add this option since we still need some compiler-specific includes */
		args_add_prefix(stripped_args, "-nostdinc");
	}

	/* Now add the compiler */
	args_add_prefix(stripped_args, compiler);

	/* Any any specified prefix */
	if ((e=getenv("UCFRONT_PREFIX"))) {
		char *p = find_executable(e, MYNAME);
		if (!p) {
			perror(e);
			exit(1);
		}
		args_add_prefix(stripped_args, p);
	}

	/* Hack by JW to allow forcing specific args right at the 
	   end of the stripped arg list.  This works around cruftiness
	   in mb-gcc-2.95.x, however it may be useful somewhere else */
	if((e=getenv("UCFRONT_LINK_SUFFIX")) && (mode==MODE_LINK) ) 
	{
		/* Break up potentially multiple words into substrings */
		char *p1;

		/* Duplicate the string - strtok messes with it */
		char *e2=(char *)malloc(strlen(e)+1);
		strcpy(e2,e);

		p1=strtok(e2," ");

		while(p1)
		{
			args_add(stripped_args,p1);
			p1=strtok(NULL," ");
		}
		free(e2);
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
	find_compiler(argc, argv);

	if (ucfront_debug) {
		cc_log("Original: ");
		log_args(orig_args);
	}

	if (getenv("UCFRONT_DISABLE")) {
		invoke_original_compiler();
	}

	/* load remapped directories */
	parse_map_dirs(getenv("UCFRONT_MAPDIRS"));
	
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
	printf("ucfront, a uClinux compiler front end. Version %s\n", UCFRONT_VERSION);
	printf("Copyright Steve Bennett, 2005\n\n");
	
	printf("Usage:\n");
	printf("\tucfront [options]\n");
	printf("\tucfront<anything> compiler [compile options]\n");
	printf("\tcompiler [compile options]    (via symbolic link)\n");
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
			printf("ucfront version %s\n", UCFRONT_VERSION);
			printf("Copyright Steve Bennett 2005\n");
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

	/* check for c++ */
	if (strlen(argv[0]) > 2 && strcmp(argv[0] + strlen(argv[0]) - 2, "++") == 0)
		cplusplus = 1;

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
