/* New simplified depmod without backwards compat stuff and not
   requiring ksyms.

   (C) 2002 Rusty Russell IBM Corporation
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sys/mman.h>

#include "zlibsupport.h"
#include "depmod.h"
#include "moduleops.h"
#include "tables.h"

#include "testing.h"

#ifndef MODULE_DIR
#define MODULE_DIR "/lib/modules/"
#endif

static int verbose;
static unsigned int skipchars;

void fatal(const char *fmt, ...)
{
	va_list arglist;

	fprintf(stderr, "FATAL: ");

	va_start(arglist, fmt);
	vfprintf(stderr, fmt, arglist);
	va_end(arglist);

	exit(1);
}

void warn(const char *fmt, ...)
{
	va_list arglist;

	fprintf(stderr, "WARNING: ");

	va_start(arglist, fmt);
	vfprintf(stderr, fmt, arglist);
	va_end(arglist);
}

void *do_nofail(void *ptr, const char *file, int line, const char *expr)
{
	if (!ptr) {
		fatal("Memory allocation failure %s line %d: %s.\n",
		      file, line, expr);
	}
	return ptr;
}

#define SYMBOL_HASH_SIZE 1024
struct symbol
{
	struct symbol *next;
	struct module *owner;
	char name[0];
};

static struct symbol *symbolhash[SYMBOL_HASH_SIZE];

/* This is based on the hash agorithm from gdbm, via tdb */
static inline unsigned int tdb_hash(const char *name)
{
	unsigned value;	/* Used to compute the hash value.  */
	unsigned   i;	/* Used to cycle through random values. */

	/* Set the initial value from the key size. */
	for (value = 0x238F13AF * strlen(name), i=0; name[i]; i++)
		value = (value + (((unsigned char *)name)[i] << (i*5 % 24)));

	return (1103515243 * value + 12345);
}

void add_symbol(const char *name, struct module *owner)
{
	unsigned int hash;
	struct symbol *new = NOFAIL(malloc(sizeof *new + strlen(name) + 1));

	new->owner = owner;
	strcpy(new->name, name);

	hash = tdb_hash(name) % SYMBOL_HASH_SIZE;
	new->next = symbolhash[hash];
	symbolhash[hash] = new;
}

static int print_unknown;

struct module *find_symbol(const char *name, const char *modname, int weak)
{
	struct symbol *s;

	/* For our purposes, .foo matches foo.  PPC64 needs this. */
	if (name[0] == '.')
		name++;

	for (s = symbolhash[tdb_hash(name) % SYMBOL_HASH_SIZE]; s; s=s->next) {
		if (streq(s->name, name))
			return s->owner;
	}

	if (print_unknown && !weak)
		warn("%s needs unknown symbol %s\n", modname, name);

	return NULL;
}

void add_dep(struct module *mod, struct module *depends_on)
{
	unsigned int i;

	for (i = 0; i < mod->num_deps; i++)
		if (mod->deps[i] == depends_on)
			return;

	mod->deps = NOFAIL(realloc(mod->deps, sizeof(mod->deps[0])*(mod->num_deps+1)));
	mod->deps[mod->num_deps++] = depends_on;
}

static void load_system_map(const char *filename)
{
	FILE *system_map;
	char line[10240];

	system_map = fopen(filename, "r");
	if (!system_map)
		fatal("Could not open '%s': %s\n", filename, strerror(errno));

	/* eg. c0294200 R __ksymtab_devfs_alloc_devnum */
	while (fgets(line, sizeof(line)-1, system_map)) {
		char *ptr;

		/* Snip \n */
		ptr = strchr(line, '\n');
		*ptr = '\0';

		ptr = strchr(line, ' ');
		if (!ptr || !(ptr = strchr(ptr + 1, ' ')))
			continue;

		/* Covers gpl-only and normal symbols. */
		if (strncmp(ptr+1, "__ksymtab_", strlen("__ksymtab_")) == 0)
			add_symbol(ptr+1+strlen("__ksymtab_"), NULL);
	}

	/* __this_module is magic inserted by kernel loader. */
	add_symbol("__this_module", NULL);
	/* On S390, this is faked up too */
	add_symbol("_GLOBAL_OFFSET_TABLE_", NULL);
}

static struct option options[] = { { "all", 0, NULL, 'a' },
				   { "quick", 0, NULL, 'A' },
				   { "basedir", 1, NULL, 'b' },
				   { "errsyms", 0, NULL, 'e' },
				   { "filesyms", 1, NULL, 'F' },
				   { "help", 0, NULL, 'h' },
				   { "show", 0, NULL, 'n' },
				   { "dry-run", 0, NULL, 'n' },
				   { "quiet", 0, NULL, 'q' },
				   { "root", 0, NULL, 'r' },
				   { "unresolved-error", 0, NULL, 'u' },
				   { "verbose", 0, NULL, 'v' },
				   { "version", 0, NULL, 'V' },
				   /* Obsolete, but we need to parse it. */
				   { "config", 1, NULL, 'C' },
				   { NULL, 0, NULL, 0 } };

/* Version number or module name?  Don't assume extension. */
static int is_version_number(const char *version)
{
	unsigned int dummy;

	return (sscanf(version, "%u.%u.%u", &dummy, &dummy, &dummy) == 3);
}

static int old_module_version(const char *version)
{
	/* Expect three part version. */
	unsigned int major, sub, minor;

	sscanf(version, "%u.%u.%u", &major, &sub, &minor);

	if (major > 2) return 0;
	if (major < 2) return 1;

	/* 2.x */
	if (sub > 5) return 0;
	if (sub < 5) return 1;

	/* 2.5.x */
	if (minor >= 48) return 0;
	return 1;
}

static void exec_old_depmod(char *argv[])
{
	char *sep;
	char pathname[strlen(argv[0])+1];
	char oldname[strlen("depmod") + strlen(argv[0]) + sizeof(".old")];

	memset(pathname, 0, strlen(argv[0])+1);
	sep = strrchr(argv[0], '/');
	if (sep)
		memcpy(pathname, argv[0], sep - argv[0]+1);
	sprintf(oldname, "%s%s.old", pathname, "depmod");

	/* Recursion detection: we need an env var since we can't
	   change argv[0] (as older modutils uses it to determine
	   behavior). */
	if (getenv("MODULE_RECURSE"))
		return;
	setenv("MODULE_RECURSE", "y", 0);

	execvp(oldname, argv);
	fprintf(stderr,
		"Version requires old depmod, but couldn't run %s: %s\n",
		oldname, strerror(errno));
	exit(2);
}

static void print_usage(const char *name)
{
	fprintf(stderr,
	"%s " VERSION " -- part of " PACKAGE "\n"
	"%s -[aA] [-n -e -v -q -V -r -u]\n"
	"      [-b basedirectory] [forced_version]\n"
	"depmod [-n -e -v -q -r -u] [-F kernelsyms] module1.o module2.o ...\n"
	"If no arguments (except options) are given, \"depmod -a\" is assumed\n"
	"\n"
	"depmod will output a dependancy list suitable for the modprobe utility.\n"
	"\n"
	"\n"
	"Options:\n"
	"\t-a, --all            Probe all modules\n"
	"\t-n, --show           Write the dependency file on stdout only\n"
	"\t-V, --version        Print the release version\n"
	"\t-h, --help           Print this usage message\n"
	"\n"
	"The following options are useful for people managing distributions:\n"
	"\t-b basedirectory\n"
	"\t    --basedir basedirectory    Use an image of a module tree.\n"
	"\t-F kernelsyms\n"
	"\t    --filesyms kernelsyms      Use the file instead of the\n"
	"\t                               current kernel symbols.\n",
	"depmod", "depmod");
}

static int ends_in(const char *name, const char *ext)
{
	unsigned int namelen, extlen;

	/* Grab lengths */
	namelen = strlen(name);
	extlen = strlen(ext);

	if (namelen < extlen) return 0;

	if (streq(name + namelen - extlen, ext))
		return 1;
	return 0;
}

/* "\177ELF" <byte> where byte = 001 for 32-bit, 002 for 64 */
int needconv(const char *elfhdr)
{
	union { short s; char c[2]; } endian_test;

	endian_test.s = 1;
	if (endian_test.c[1] == 1) return elfhdr[EI_DATA] != ELFDATA2MSB;
	if (endian_test.c[0] == 1) return elfhdr[EI_DATA] != ELFDATA2LSB;
	else
		abort();
}

static struct module *grab_module(const char *dirname, const char *filename)
{
	struct module *new;

	new = NOFAIL(malloc(sizeof(*new)
			    + strlen(dirname?:"") + 1 + strlen(filename) + 1));
	if (dirname)
		sprintf(new->pathname, "%s/%s", dirname, filename);
	else
		strcpy(new->pathname, filename);

	INIT_LIST_HEAD(&new->dep_list);

	new->data = grab_file(new->pathname, &new->len);
	if (!new->data) {
		warn("Can't read module %s: %s\n",
		     new->pathname, strerror(errno));
		goto fail_data;
	}

	/* "\177ELF" <byte> where byte = 001 for 32-bit, 002 for 64 */
	if (memcmp(new->data, ELFMAG, SELFMAG) != 0) {
		warn("Module %s is not an elf object\n", new->pathname);
		goto fail;
	}

	switch (((char *)new->data)[EI_CLASS]) {
	case ELFCLASS32:
		new->ops = &mod_ops32;
		break;
	case ELFCLASS64:
		new->ops = &mod_ops64;
		break;
	default:
		warn("Module %s has elf unknown identifier %i\n",
		     new->pathname, ((char *)new->data)[EI_CLASS]);
		goto fail;
	}
	new->conv = needconv(new->data);
	return new;

fail:
	release_file(new->data, new->len);
fail_data:
	free(new);
	return NULL;
}

struct module_traverse
{
	struct module_traverse *prev;
	struct module *mod;
};

static int in_loop(struct module *mod, const struct module_traverse *traverse)
{
	const struct module_traverse *i;

	for (i = traverse; i; i = i->prev) {
		if (i->mod == mod)
			return 1;
	}
	return 0;
}

static char *basename(const char *name)
{
	const char *base = strrchr(name, '/');
	if (base) return (char *)base + 1;
	return (char *)name;
}

/* Assume we are doing all the modules, so only report each loop once. */
static void report_loop(const struct module *mod,
			const struct module_traverse *traverse)
{
	const struct module_traverse *i;

	/* Check that start is least alphabetically.  eg.  a depends
	   on b depends on a will get reported for a, not b.  */
	for (i = traverse->prev; i->prev; i = i->prev) {
		if (strcmp(mod->pathname, i->mod->pathname) > 0)
			return;
	}

	/* Is start in the loop?  If not, don't report now. eg. a
	   depends on b which depends on c which depends on b.  Don't
	   report when generating depends for a. */
	if (mod != i->mod)
		return;

	warn("Loop detected: %s ", mod->pathname);
	for (i = traverse->prev; i->prev; i = i->prev)
		fprintf(stderr, "needs %s ", basename(i->mod->pathname));
	fprintf(stderr, "which needs %s again!\n", basename(mod->pathname));
}

/* This is damn slow, but loops actually happen, and we don't want to
   just exit() and leave the user without any modules. */
static int has_dep_loop(struct module *module, struct module_traverse *prev)
{
	unsigned int i;
	struct module_traverse traverse = { .prev = prev, .mod = module };

	if (in_loop(module, prev)) {
		report_loop(module, &traverse);
		return 1;
	}

	for (i = 0; i < module->num_deps; i++)
		if (has_dep_loop(module->deps[i], &traverse))
			return 1;
	return 0;
}

/* Uniquifies and orders a dependency list. */
static void order_dep_list(struct module *start, struct module *mod)
{
	unsigned int i;

	for (i = 0; i < mod->num_deps; i++) {
		/* If it was previously depended on, move it to the
		   tail.  ie. if a needs b and c, and c needs b, we
		   must order b after c. */
		list_del(&mod->deps[i]->dep_list);
		list_add_tail(&mod->deps[i]->dep_list, &start->dep_list);
		order_dep_list(start, mod->deps[i]);
	}
}

static void del_module(struct module **modules, struct module *delme)
{
	struct module **i;

	/* Find pointer to it. */ 
	for (i = modules; *i != delme; i = &(*i)->next);

	*i = delme->next;
}

static void output_deps(struct module *modules,
			FILE *out)
{
	struct module *i;

	for (i = modules; i; i = i->next)
		i->ops->calculate_deps(i, verbose);

	/* Strip out loops. */
 again:
	for (i = modules; i; i = i->next) {
		if (has_dep_loop(i, NULL)) {
			warn("Module %s ignored, due to loop\n",
			     i->pathname + skipchars);
			del_module(&modules, i);
			goto again;
		}
	}

	/* Now dump them out. */
	for (i = modules; i; i = i->next) {
		struct list_head *j, *tmp;
		order_dep_list(i, i);

		fprintf(out, "%s:", i->pathname + skipchars);
		list_for_each_safe(j, tmp, &i->dep_list) {
			struct module *dep
				= list_entry(j, struct module, dep_list);
			fprintf(out, " %s", dep->pathname + skipchars);
			list_del_init(j);
		}
		fprintf(out, "\n");
	}
}

static int smells_like_module(const char *name)
{
	return ends_in(name,".ko") || ends_in(name, ".ko.gz");
}

typedef struct module *(*do_module_t)(const char *dirname,
				      const char *filename,
				      struct module *next);

static int is_update(const char *dirname)
{
	char *p;

	p = strstr(dirname, "updates");
	if (!p)
		return 0;
	return (p[strlen("updates")] == '/' || p[strlen("updates")] == '\0');
}

/* Grab everything not under updates/ directories. */
static struct module *do_normal_module(const char *dirname,
				       const char *filename,
				       struct module *list)
{
	struct module *new;

	if (is_update(dirname))
		return list;
	new = grab_module(dirname, filename);
	if (!new)
		return list;
	new->next = list;
	return new;
}

/* Grab everything under updates/ directories, override existing module. */
static struct module *do_update_module(const char *dirname,
				       const char *filename,
				       struct module *list)
{
	struct module *new, **i;

	if (!is_update(dirname))
		return list;

	new = grab_module(dirname, filename);
	if (!new)
		return list;

	/* Find module of same name, and replace it. */
	for (i = &list; *i; i = &(*i)->next) {
		if (streq(basename((*i)->pathname), filename)) {
			new->next = (*i)->next;
			*i = new;
			return list;
		}
	}

	/* Update of non-existent module.  Just prepend. */
	new->next = list;
	return new;
}

static struct module *grab_dir(const char *dirname,
			       DIR *dir,
			       struct module *next,
			       do_module_t do_mod)
{
	struct dirent *dirent;

	while ((dirent = readdir(dir)) != NULL) {
		if (smells_like_module(dirent->d_name))
			next = do_mod(dirname, dirent->d_name, next);
		else if (!streq(dirent->d_name, ".")
			 && !streq(dirent->d_name, "..")) {
			DIR *sub;
			char dummy; /* readlink with 0 len always fails */
			char subdir[strlen(dirname) + 1
				   + strlen(dirent->d_name) + 1];
			sprintf(subdir, "%s/%s", dirname, dirent->d_name);
			/* Don't follow links, eg. build/ */
			if (readlink(subdir, &dummy, 1) < 0) {
				sub = opendir(subdir);
				if (sub) {
					next = grab_dir(subdir, sub, next,
							do_mod);
					closedir(sub);
				}
			}
		}
	}
	return next;
}


/* RH-ism: updates/ dir overrides other modules. */
static struct module *grab_basedir(const char *dirname)
{
	DIR *dir;
	struct module *list;
	char updatedir[strlen(dirname) + sizeof("/updates")];

	dir = opendir(dirname);
	if (!dir) {
		warn("Couldn't open directory %s: %s\n",
		     dirname, strerror(errno));
		return NULL;
	}
	list = grab_dir(dirname, dir, NULL, do_normal_module);
	closedir(dir);

	sprintf(updatedir, "%s/updates", dirname);
	dir = opendir(updatedir);
	if (dir) {
		list = grab_dir(updatedir, dir, list, do_update_module);
		closedir(dir);
	}
	return list;
}

static void parse_modules(struct module *list)
{
	struct module *i;

	for (i = list; i; i = i->next) {
		i->ops->load_symbols(i);
		i->ops->fetch_tables(i);
	}
}

/* Convert filename to the module name.  Works if filename == modname, too. */
static void filename2modname(char *modname, const char *filename)
{
	const char *afterslash;
	unsigned int i;

	afterslash = strrchr(filename, '/');
	if (!afterslash)
		afterslash = filename;
	else
		afterslash++;

	/* Convert to underscores, stop at first . */
	for (i = 0; afterslash[i] && afterslash[i] != '.'; i++) {
		if (afterslash[i] == '-')
			modname[i] = '_';
		else
			modname[i] = afterslash[i];
	}
	modname[i] = '\0';
}

/* Simply dump hash table. */
static void output_symbols(struct module *unused, FILE *out)
{
	unsigned int i;

	fprintf(out, "# Aliases for symbols, used by symbol_request().\n");
	for (i = 0; i < SYMBOL_HASH_SIZE; i++) {
		struct symbol *s;

		for (s = symbolhash[i]; s; s = s->next) {
			if (s->owner) {
				char modname[strlen(s->owner->pathname)+1];
				filename2modname(modname, s->owner->pathname);
				fprintf(out, "alias symbol:%s %s\n",
					s->name, modname);
			}
		}
	}
}

static const char *next_string(const char *string, unsigned long *secsize)
{
	/* Skip non-zero chars */
	while (string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}

	/* Skip any zero padding. */
	while (!string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}
	return string;
}

static void output_aliases(struct module *modules, FILE *out)
{
	struct module *i;
	const char *p;
	unsigned long size;

	fprintf(out, "# Aliases extracted from modules themselves.\n");
	for (i = modules; i; i = i->next) {
		char modname[strlen(i->pathname)+1];

		filename2modname(modname, i->pathname);

		/* Grab from old-style .modalias section. */
		for (p = i->ops->get_aliases(i, &size);
		     p;
		     p = next_string(p, &size))
			fprintf(out, "alias %s %s\n", p, modname);

		/* Grab form new-style .modinfo section. */
		for (p = i->ops->get_modinfo(i, &size);
		     p;
		     p = next_string(p, &size)) {
			if (strncmp(p, "alias=", strlen("alias=")) == 0)
				fprintf(out, "alias %s %s\n",
					p + strlen("alias="), modname);
		}
	}
}

struct depfile {
	char *name;
	void (*func)(struct module *, FILE *);
};

static struct depfile depfiles[] = {
	{ "modules.dep", output_deps }, /* This is what we check for '-A'. */
	{ "modules.pcimap", output_pci_table },
	{ "modules.usbmap", output_usb_table },
	{ "modules.ccwmap", output_ccw_table },
	{ "modules.ieee1394map", output_ieee1394_table },
	{ "modules.isapnpmap", output_isapnp_table },
	{ "modules.inputmap", output_input_table },
	{ "modules.ofmap", output_of_table },
	{ "modules.seriomap", output_serio_table },
	{ "modules.alias", output_aliases },
	{ "modules.symbols", output_symbols },
};

/* If we can't figure it out, it's safe to say "true". */
static int any_modules_newer(const char *dirname, time_t mtime)
{
	DIR *dir;
	struct dirent *dirent;

	dir = opendir(dirname);
	if (!dir)
		return 1;

	while ((dirent = readdir(dir)) != NULL) {
		struct stat st;
		char file[strlen(dirname) + 1 + strlen(dirent->d_name) + 1];

		if (streq(dirent->d_name, ".") || streq(dirent->d_name, ".."))
			continue;

		sprintf(file, "%s/%s", dirname, dirent->d_name);
		if (lstat(file, &st) != 0)
			return 1;

		if (smells_like_module(dirent->d_name)) {
			if (st.st_mtime > mtime)
				return 1;
		} else if (S_ISDIR(st.st_mode)) {
			if (any_modules_newer(file, mtime))
				return 1;
		}
	}
	closedir(dir);
	return 0;
}

static int depfile_out_of_date(const char *dirname)
{
	struct stat st;
	char depfile[strlen(dirname) + 1 + strlen(depfiles[0].name) + 1];

	sprintf(depfile, "%s/%s", dirname, depfiles[0].name);

	if (stat(depfile, &st) != 0)
		return 1;

	return any_modules_newer(dirname, st.st_mtime);
}

int main(int argc, char *argv[])
{
	int opt, all = 0, maybe_all = 0, doing_stdout = 0;
	char *basedir = "", *dirname, *version, *badopt = NULL,
		*system_map = NULL;
	struct module *list = NULL;
	int i;

	/* Don't print out any errors just yet, we might want to exec
           backwards compat version. */
	opterr = 0;
	while ((opt = getopt_long(argc, argv, "ab:ArehnqruvVF:C:", options, NULL))
	       != -1) {
		switch (opt) {
		case 'a':
			all = 1;
			break;
		case 'b':
			basedir = optarg;
			skipchars = strlen(basedir);
			break;
		case 'A':
			maybe_all = 1;
			break;
		case 'F':
			system_map = optarg;
			break;
		case 'e':
			print_unknown = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'u':
		case 'q':
		case 'r':
		case 'C':
			/* Ignored. */
			break;
		case 'h':
			print_usage(argv[0]);
			exit(0);
			break;
		case 'n':
			doing_stdout = 1;
			break;
		case 'V':
			printf("%s %s\n", PACKAGE, VERSION);
			exit(0);
		default:
			badopt = argv[optind-1];
		}
	}

	/* We can't print unknowns without a System.map */
	if (!system_map)
		print_unknown = 0;
	else
		load_system_map(system_map);

	/* They can specify the version naked on the command line */
	if (optind < argc && is_version_number(argv[optind])) {
		version = strdup(argv[optind]);
		optind++;
	} else {
		struct utsname buf;
		uname(&buf);
		version = strdup(buf.release);
	}

	/* Run old version if required. */
	if (old_module_version(version))
		exec_old_depmod(argv);

	if (badopt) {
		fprintf(stderr, "%s: malformed/unrecognized option '%s'\n",
			argv[0], badopt);
		print_usage(argv[0]);
		exit(1);
	}

	/* Depmod -a by default if no names. */
	if (optind == argc)
		all = 1;

	dirname = NOFAIL(malloc(strlen(basedir)
			 + strlen(MODULE_DIR)
			 + strlen(version) + 1));
	sprintf(dirname, "%s%s%s", basedir, MODULE_DIR, version);

	if (maybe_all) {
		if (!doing_stdout && !depfile_out_of_date(dirname))
			exit(0);
		all = 1;
	}

	if (!all) {
		/* Do command line args. */
		for (opt = optind; opt < argc; opt++) {
			struct module *new = grab_module(NULL, argv[opt]);
			if (new) {
				new->next = list;
				list = new;
			}
		}
	} else {
		list = grab_basedir(dirname);
	}
	parse_modules(list);

	for (i = 0; i < sizeof(depfiles)/sizeof(depfiles[0]); i++) {
		FILE *out;
		struct depfile *d = &depfiles[i];
		char depname[strlen(dirname) + 1 + strlen(d->name) + 1];
		char tmpname[strlen(dirname) + 1 + strlen(d->name) +
						strlen(".temp") + 1];

		sprintf(depname, "%s/%s", dirname, d->name);
		sprintf(tmpname, "%s/%s.temp", dirname, d->name);
		if (!doing_stdout) {
			out = fopen(tmpname, "w");
			if (!out)
				fatal("Could not open %s for writing: %s\n",
					tmpname, strerror(errno));
		} else
			out = stdout;
		d->func(list, out);
		if (!doing_stdout) {
			fclose(out);
			if (rename(tmpname, depname) < 0)
				fatal("Could not rename %s into %s: %s\n",
					tmpname, depname, strerror(errno));
		}
	}

	free(dirname);
	free(version);
	
	return 0;
}
