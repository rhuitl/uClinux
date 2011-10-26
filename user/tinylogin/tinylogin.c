/* vi: set sw=4 ts=4: */
#include "tinylogin.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#undef APPLET
#undef APPLET_NOUSAGE
#undef PROTOTYPES
#include "applets.h"

static int been_there_done_that = 0;
const char *applet_name;

#ifdef TLG_FEATURE_INSTALLER
/* 
 * directory table
 *		this should be consistent w/ the enum, tinylogin.h::Location,
 *		or else...
 */
static char *install_dir[] = {
	"/",
	"/bin",
	"/sbin",
	"/usr/bin",
	"/usr/sbin",
};

/* abstract link() */
typedef int (*__link_f) (const char *, const char *);

/* 
 * Where in the filesystem is this tinylogin?
 * [return]
 *		malloc'd string w/ full pathname of tinylogin's location
 *		NULL on failure
 */
static char *tinylogin_fullpath()
{
	pid_t pid;
	char path[256];
	char proc[256];
	int len;

	pid = getpid();
	sprintf(proc, "/proc/%d/exe", pid);
	len = readlink(proc, path, 256);
	if (len != -1) {
		path[len] = 0;
	} else {
		fprintf(stderr, "%s: %s\n", proc, strerror(errno));
		return NULL;
	}
	return strdup(path);
}

/* create (sym)links for each applet */
static void install_links(const char *tinylogin, int use_symbolic_links)
{
	__link_f Link = link;

	char command[256];
	int i;
	int rc;

	if (use_symbolic_links)
		Link = symlink;

	for (i = 0; applets[i].name != NULL; i++) {
		sprintf(command, "%s/%s",
				install_dir[applets[i].location], applets[i].name);
		rc = Link(tinylogin, command);

		if (rc) {
			fprintf(stderr, "%s: %s\n", command, strerror(errno));
		}
	}
}

#endif							/* TLG_FEATURE_INSTALLER */

int applet_name_compare(const void *x, const void *y)
{
	const struct Applet *applet1 = x;
	const struct Applet *applet2 = y;

	return strcmp(applet1->name, applet2->name);
}


int main(int argc, char **argv)
{
	struct Applet search_applet, *applet;
	const char *s;

	applet_name = "tinylogin";

#ifdef TLG_FEATURE_INSTALLER
	/* 
	 * This style of argument parsing doesn't scale well 
	 * in the event that tinylogin starts wanting more --options.
	 * If someone has a cleaner approach, by all means implement it.
	 */
	if (argc > 1 && (strcmp(argv[1], "--install") == 0)) {
		int use_symbolic_links = 0;
		int rc = 0;
		char *tinylogin;

		/* to use symlinks, or not to use symlinks... */
		if (argc > 2) {
			if ((strcmp(argv[2], "-s") == 0)) {
				use_symbolic_links = 1;
			}
		}

		/* link */
		tinylogin = tinylogin_fullpath();
		if (tinylogin) {
			install_links(tinylogin, use_symbolic_links);
			free(tinylogin);
		} else {
			rc = 1;
		}
		return rc;
	}
#endif							/* TLG_FEATURE_INSTALLER */

	for (s = applet_name = argv[0]; *s != '\0';) {
		if (*s++ == '/')
			applet_name = s;
	}

	/* Do a binary search to find the applet entry given the name. */
	search_applet.name = applet_name;
	applet = bsearch(&search_applet, applets, NUM_APPLETS,
					 sizeof(struct Applet), applet_name_compare);

	if (applet != NULL) {
		if (applet->usage && argv[1] && strcmp(argv[1], "--help") == 0)
			usage(applet->usage);

		/* Drop permissions if possible (in case we are setuid root) */
		if (applet->need_suid != TRUE) {
			setuid(getuid());
			setgid(getgid());
		}
		exit((*(applet->main)) (argc, argv));
	}

	return (tinylogin_main(argc, argv));
}


int tinylogin_main(int argc, char **argv)
{
	int col = 0, len, i;

	argc--;

	/* If we've already been here once, exit now */
	if (been_there_done_that == 1 || argc < 1) {
		const struct Applet *a = applets;

		fprintf(stderr, "TinyLogin v%s (%s) multi-call binary -- GPL2\n\n"
				"Usage: tinylogin [function] [arguments]...\n"
				"   or: [function] [arguments]...\n\n"
				"\tTinyLogin is a multi-call binary that combines several tiny Unix\n"
				"\tutilities for handling logins, user authentication, changing passwords,\n"
				"\tand otherwise maintaining users and groups on an embedded system.  Most\n"
				"\tpeople will create a link to TinyLogin for each function they wish to\n"
				"\tuse, and TinyLogin will act like whatever it was invoked as.\n"
				"\nCurrently defined functions:\n", TLG_VER, TLG_BT);

		while (a->name != 0) {
			col +=
				fprintf(stderr, "%s%s", ((col == 0) ? "\t" : ", "),
						(a++)->name);
			if (col > 60 && a->name != 0) {
				fprintf(stderr, ",\n");
				col = 0;
			}
		}
		fprintf(stderr, "\n\n");
		exit(-1);
	}

	/* Flag that we've been here already */
	been_there_done_that = 1;

	/* Move the command line down a notch */
	len = argv[argc] + strlen(argv[argc]) - argv[1];
	memmove(argv[0], argv[1], len);
	memset(argv[0] + len, 0, argv[1] - argv[0]);

	/* Fix up the argv pointers */
	len = argv[1] - argv[0];
	memmove(argv, argv + 1, sizeof(char *) * (argc + 1));

	for (i = 0; i < argc; i++)
		argv[i] -= len;

	return (main(argc, argv));
}

/*
Local Variables:
c-file-style: "linux"
c-basic-offset: 4
tab-width: 4
End:
*/
