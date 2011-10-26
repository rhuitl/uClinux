/* ulogd, Version $LastChangedRevision: 805 $
 *
 * $Id: ulogd.c 805 2005-04-18 14:39:10Z laforge $
 *
 * userspace logging daemon for the iptables ULOG target
 * of the linux 2.4 netfilter subsystem.
 *
 * (C) 2000-2003 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: ulogd.c 805 2005-04-18 14:39:10Z laforge $
 *
 * Modifications:
 * 	14 Jun 2001 Martin Josefsson <gandalf@wlug.westbo.se>
 * 		- added SIGHUP handler for logfile cycling
 *
 * 	10 Feb 2002 Alessandro Bono <a.bono@libero.it>
 * 		- added support for non-fork mode
 * 		- added support for logging to stdout
 *
 * 	09 Sep 2003 Magnus Boden <sarek@ozaba.cx>
 * 		- added support for more flexible multi-section conffile
 *
 * 	20 Apr 2004 Nicolas Pougetoux <nicolas.pougetoux@edelweb.fr>
 * 		- added suppurt for seteuid()
 */

#define ULOGD_VERSION	"1.23"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <libipulog/libipulog.h>
#include <ulogd/conffile.h>
#include <ulogd/ulogd.h>

/* Size of the socket recevive memory.  Should be at least the same size as the
 * 'nlbufsiz' module loadtime parameter of ipt_ULOG.o
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define ULOGD_RMEM_DEFAULT	131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define ULOGD_BUFSIZE_DEFAULT	150000

#ifdef DEBUG
#define DEBUGP(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGP(format, args...) 
#endif

/* default config parameters, if not changed in configfile */
#ifndef ULOGD_LOGFILE_DEFAULT
#define ULOGD_LOGFILE_DEFAULT	"/var/log/ulogd.log"
#endif
#ifndef ULOGD_NLGROUP_DEFAULT
#define ULOGD_NLGROUP_DEFAULT	32
#endif

/* where to look for the config file */
#ifndef ULOGD_CONFIGFILE
#define ULOGD_CONFIGFILE	"/etc/ulogd.conf"
#endif

/* global variables */
static struct ipulog_handle *libulog_h;	/* our libipulog handle */
static unsigned char* libulog_buf;	/* the receive buffer */
static int loglevel = 1;		/* current loglevel */
static char *ulogd_configfile = ULOGD_CONFIGFILE;

FILE *logfile = NULL;			/* logfile pointer */

/* linked list for all registered interpreters */
static ulog_interpreter_t *ulogd_interpreters;

/* linked list for all registered output targets */
static ulog_output_t *ulogd_outputs;

/***********************************************************************
 * INTERPRETER AND KEY HASH FUNCTIONS 			(new in 0.9)
 ***********************************************************************/

/* We keep hashtables of interpreters and registered keys. The hash-tables
 * are allocated dynamically at program load time. You may control the
 * allocation granularity of both hashes (i.e. the amount of hashtable
 * entries are allocated at one time) through modification of the constants
 * INTERH_ALLOC_GRAN and KEYH_ALLOC_GRAN 
 */

/* allocation granularith */
#define INTERH_ALLOC_GRAN	5

/* hashtable for all registered interpreters */
static ulog_interpreter_t **ulogd_interh;

/* current hashtable size */
static unsigned int ulogd_interh_ids_alloc;

/* total number of registered ids */
static unsigned int ulogd_interh_ids;

/* allocate a new interpreter id and write it into the interpreter struct */
static unsigned int interh_allocid(ulog_interpreter_t *ip)
{
	unsigned int id;

	id = ++ulogd_interh_ids;
	
	if (id >= ulogd_interh_ids_alloc) {
		if (!ulogd_interh)
			ulogd_interh = (ulog_interpreter_t **) 
				malloc(INTERH_ALLOC_GRAN *
					sizeof(ulog_interpreter_t));
		else
			ulogd_interh = (ulog_interpreter_t **)
				realloc(ulogd_interh, 
					(INTERH_ALLOC_GRAN +
					 ulogd_interh_ids_alloc) *
					sizeof(ulog_interpreter_t));

		ulogd_interh_ids_alloc += INTERH_ALLOC_GRAN;
	}

	ip->id = id;
	ulogd_interh[id] = ip;
	return id;
}

/* get interpreter id by name */
unsigned int interh_getid(const char *name)
{
	unsigned int i;
	for (i = 1; i <= ulogd_interh_ids; i++)
		if (!strcmp(name, (ulogd_interh[i])->name))
			return i;

	return 0;
}

#ifdef DEBUG
/* dump out the contents of the interpreter hash */
static void interh_dump(void)
{
	unsigned int i;

	for (i = 1; i <= ulogd_interh_ids; i++)
		ulogd_log(ULOGD_DEBUG, "ulogd_interh[%d] = %s\n", 
			i, (ulogd_interh[i])->name);

}
#endif

/* key hash allocation granularity */
#define KEYH_ALLOC_GRAN 20

/* hash table for key ids */
struct ulogd_keyh_entry *ulogd_keyh;

/* current size of the hashtable */
static unsigned int ulogd_keyh_ids_alloc;

/* total number of registered keys */
static unsigned int ulogd_keyh_ids;

/* allocate a new key_id */
static unsigned int keyh_allocid(ulog_interpreter_t *ip, unsigned int offset,
				const char *name)
{
	unsigned int id;

	id = ++ulogd_keyh_ids;

	if (id >= ulogd_keyh_ids_alloc) {
		if (!ulogd_keyh) {
			ulogd_keyh = (struct ulogd_keyh_entry *)
				malloc(KEYH_ALLOC_GRAN * 
					sizeof(struct ulogd_keyh_entry));
			if (!ulogd_keyh) {
				ulogd_log(ULOGD_ERROR, "OOM!\n");
				return 0;
			}
		} else {
			ulogd_keyh = (struct ulogd_keyh_entry *)
				realloc(ulogd_keyh, (KEYH_ALLOC_GRAN
						+ulogd_keyh_ids_alloc) *
					sizeof(struct ulogd_keyh_entry));

			if (!ulogd_keyh) {
				ulogd_log(ULOGD_ERROR, "OOM!\n");
				return 0;
			}
		}

		ulogd_keyh_ids_alloc += KEYH_ALLOC_GRAN;
	}

	ulogd_keyh[id].interp = ip;
	ulogd_keyh[id].offset = offset;
	ulogd_keyh[id].name = name;

	return id;
}

#ifdef DEBUG
/* dump the keyhash to standard output */
static void keyh_dump(void)
{
	unsigned int i;

	printf("dumping keyh\n");
	for (i = 1; i <= ulogd_keyh_ids; i++)
		printf("ulogd_keyh[%lu] = %s:%u\n", i, 
			ulogd_keyh[i].interp->name, ulogd_keyh[i].offset);
}
#endif

/* get keyid by name */
unsigned int keyh_getid(const char *name)
{
	unsigned int i;
	for (i = 1; i <= ulogd_keyh_ids; i++)
		if (!strcmp(name, ulogd_keyh[i].name))
			return i;

	return 0;
}

/* get key name by keyid */
char *keyh_getname(unsigned int id)
{
	if (id > ulogd_keyh_ids) {
		ulogd_log(ULOGD_NOTICE, 
			"keyh_getname called with invalid id%u\n", id);
		return NULL;
	}
		
	return ulogd_keyh[id].interp->name;
}

/* get result for given key id. does not check if result valid */
ulog_iret_t *keyh_getres(unsigned int id)
{
	ulog_iret_t *ret;

	if (id > ulogd_keyh_ids) {
		ulogd_log(ULOGD_NOTICE,
			"keyh_getres called with invalid id %d\n", id);
		return NULL;
	}

	ret = &ulogd_keyh[id].interp->result[ulogd_keyh[id].offset];

	return ret;
}

/***********************************************************************
 * INTERPRETER MANAGEMENT 
 ***********************************************************************/

/* try to lookup a registered interpreter for a given name */
static ulog_interpreter_t *find_interpreter(const char *name)
{
	unsigned int id;
	
	id = interh_getid(name);
	if (!id)
		return NULL;

	return ulogd_interh[id];
}

/* the function called by all interpreter plugins for registering their
 * target. */ 
void register_interpreter(ulog_interpreter_t *me)
{
	unsigned int i;

	/* check if we already have an interpreter with this name */
	if (find_interpreter(me->name)) {
		ulogd_log(ULOGD_NOTICE, 
			"interpreter `%s' already registered\n", me->name);
		return;
	}

	ulogd_log(ULOGD_INFO, "registering interpreter `%s'\n", me->name);

	/* allocate a new interpreter id for it */
	if (!interh_allocid(me)) {
		ulogd_log(ULOGD_ERROR, "unable to obtain interh_id for "
			"interpreter '%s'\n", me->name);
		return;
	}

	/* - allocate one keyh_id for each result of this interpreter 
	 * - link the elements to each other */
	for (i = 0; i < me->key_num; i++) {
		if (!keyh_allocid(me, i, me->result[i].key)) {
			ulogd_log(ULOGD_ERROR, "unable to obtain keyh_id "
				"for interpreter %s, key %d", me->name,
				me->result[i].key);
			continue;
		}
		if (i != me->key_num - 1)
			me->result[i].next = &me->result[i+1];
	}

	/* all work done, we can prepend the new interpreter to the list */
	if (ulogd_interpreters)
		me->result[me->key_num - 1].next = 
					&ulogd_interpreters->result[0];
	me->next = ulogd_interpreters;
	ulogd_interpreters = me;
}

/***********************************************************************
 * OUTPUT MANAGEMENT 
 ***********************************************************************/

/* try to lookup a registered output plugin for a given name */
static ulog_output_t *find_output(const char *name)
{
	ulog_output_t *ptr;

	for (ptr = ulogd_outputs; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
				return ptr;
	}

	return NULL;
}

/* the function called by all output plugins for registering themselves */
void register_output(ulog_output_t *me)
{
	if (find_output(me->name)) {
		ulogd_log(ULOGD_NOTICE, "output `%s' already registered\n",
				me->name);
		exit(EXIT_FAILURE);
	}
	ulogd_log(ULOGD_NOTICE, "registering output `%s'\n", me->name);
	me->next = ulogd_outputs;
	ulogd_outputs = me;
}

/***********************************************************************
 * MAIN PROGRAM
 ***********************************************************************/

static FILE syslog_dummy;

static inline int ulogd2syslog_level(int level)
{
	int syslog_level = LOG_WARNING;

	switch (level) {
		case ULOGD_DEBUG:
			syslog_level = LOG_DEBUG;
			break;
		case ULOGD_INFO:
			syslog_level = LOG_INFO;
			break;
		case ULOGD_NOTICE:
			syslog_level = LOG_NOTICE;
			break;
		case ULOGD_ERROR:
			syslog_level = LOG_ERR;
			break;
		case ULOGD_FATAL:
			syslog_level = LOG_CRIT;
			break;
	}
	return syslog_level;
}

/* log message to the logfile */
void __ulogd_log(int level, char *file, int line, const char *format, ...)
{
	char *timestr;
	va_list ap;
	time_t tm;
	FILE *outfd;

	/* log only messages which have level at least as high as loglevel */
	if (level < loglevel)
		return;

	if (logfile == &syslog_dummy) {
		/* FIXME: this omit's the 'file' string */
		va_start(ap, format);
		vsyslog(ulogd2syslog_level(level), format, ap);
		va_end(ap);
	} else {
		if (logfile)
			outfd = logfile;
		else
			outfd = stderr;

		va_start(ap, format);

		tm = time(NULL);
		timestr = ctime(&tm);
		timestr[strlen(timestr)-1] = '\0';
		fprintf(outfd, "%s <%1.1d> %s:%d ", timestr, level, file, line);
		
		vfprintf(outfd, format, ap);
		va_end(ap);

		/* flush glibc's buffer */
		fflush(outfd);
	}
}

/* propagate results to all registered output plugins */
static void propagate_results(ulog_iret_t *ret)
{
	ulog_output_t *p;

	for (p = ulogd_outputs; p; p = p->next) {
		(*p->output)(ret);
	}
}

/* clean results (set all values to 0 and free pointers) */
static void clean_results(ulog_iret_t *ret)
{
	ulog_iret_t *r;

	for (r = ret; r; r = r->next) {
		if (r->flags & ULOGD_RETF_FREE) {
			free(r->value.ptr);
			r->value.ptr = NULL;
		}
		memset(&r->value, 0, sizeof(r->value));
		r->flags &= ~ULOGD_RETF_VALID;
	}
}

/* call all registered interpreters and hand the results over to 
 * propagate_results */
static void handle_packet(ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret;
        ulog_iret_t *allret = NULL;
	ulog_interpreter_t *ip;

	unsigned int i,j;

	/* If there are no interpreters registered yet,
	 * ignore this packet */
	if (!ulogd_interh_ids) {
		ulogd_log(ULOGD_NOTICE, 
			  "packet received, but no interpreters found\n");
		return;
	}

	for (i = 1; i <= ulogd_interh_ids; i++) {
		ip = ulogd_interh[i];
		/* call interpreter */
		if ((ret = ((ip)->interp)(ip, pkt))) {
			/* create references for result linked-list */
			for (j = 0; j < ip->key_num; j++) {
				if (IS_VALID(ip->result[j])) {
					ip->result[j].cur_next = allret;
					allret = &ip->result[j];
				}
			}
		}
	}
	propagate_results(allret);
	clean_results(ulogd_interpreters->result);
}

/* plugin loader to dlopen() a plugins */
static int load_plugin(char *file)
{
	if (!dlopen(file, RTLD_NOW)) {
		ulogd_log(ULOGD_ERROR, "load_plugins: '%s': %s\n", file,
			  dlerror());
		return 1;
	}
	return 0;
}

/* open the logfile */
static int logfile_open(const char *name)
{
	if (!strcmp(name, "syslog")) {
		openlog("ulogd", LOG_PID, LOG_DAEMON);
		logfile = &syslog_dummy;
	} else if (!strcmp(name,"stdout"))
		logfile = stdout;
	else {
		logfile = fopen(name, "a");
		if (!logfile) {
			fprintf(stderr, "ERROR: can't open logfile %s: %s\n", 
				name, strerror(errno));
			exit(2);
		}
	}
	ulogd_log(ULOGD_INFO, "ulogd Version %s starting\n", ULOGD_VERSION);
	return 0;
}

/* wrapper to handle conffile error codes */
static int parse_conffile(const char *section, config_entry_t *ce)
{
	int err;

	err = config_parse_file(section, ce);

	switch(err) {
		case 0:
			return 0;
			break;
		case -ERROPEN:
			ulogd_log(ULOGD_ERROR,
				"unable to open configfile: %s\n",
				ulogd_configfile);
			break;
		case -ERRMAND:
			ulogd_log(ULOGD_ERROR,
				"mandatory option \"%s\" not found\n",
				config_errce->key);
			break;
		case -ERRMULT:
			ulogd_log(ULOGD_ERROR,
				"option \"%s\" occurred more than once\n",
				config_errce->key);
			break;
		case -ERRUNKN:
			ulogd_log(ULOGD_ERROR,
				"unknown config key \"%s\"\n",
				config_errce->key);
			break;
		case -ERRSECTION:
			ulogd_log(ULOGD_ERROR,
				"section \"%s\" not found\n", section);
			break;
	}
	return 1;

}

/* configuration directives of the main program */
static config_entry_t logf_ce = { NULL, "logfile", CONFIG_TYPE_STRING, 
				  CONFIG_OPT_NONE, 0, 
				  { string: ULOGD_LOGFILE_DEFAULT } };

static config_entry_t bufsiz_ce = { &logf_ce, "bufsize", CONFIG_TYPE_INT,       
				   CONFIG_OPT_NONE, 0,
				   { value: ULOGD_BUFSIZE_DEFAULT } }; 

static config_entry_t plugin_ce = { &bufsiz_ce, "plugin", CONFIG_TYPE_CALLBACK,
				    CONFIG_OPT_MULTI, 0, 
				    { parser: &load_plugin } };

static config_entry_t nlgroup_ce = { &plugin_ce, "nlgroup", CONFIG_TYPE_INT,
				     CONFIG_OPT_NONE, 0,
				     { value: ULOGD_NLGROUP_DEFAULT } };

static config_entry_t loglevel_ce = { &nlgroup_ce, "loglevel", CONFIG_TYPE_INT,
				      CONFIG_OPT_NONE, 0, 
				      { value: 1 } };
static config_entry_t rmem_ce = { &loglevel_ce, "rmem", CONFIG_TYPE_INT,
				  CONFIG_OPT_NONE, 0, 
				  { value: ULOGD_RMEM_DEFAULT } };

static void sigterm_handler(int signal)
{
	ulog_output_t *p;
	
	ulogd_log(ULOGD_NOTICE, "sigterm received, exiting\n");

	ipulog_destroy_handle(libulog_h);
	free(libulog_buf);
	if (logfile != stdout && logfile != &syslog_dummy)
		fclose(logfile);

	for (p = ulogd_outputs; p; p = p->next) {
		if (p->fini)
			(*p->fini)();
	}

	exit(0);
}

static void sighup_handler(int signal)
{
	ulog_output_t *p;

	if (logfile != stdout && logfile != &syslog_dummy) {
		fclose(logfile);
		logfile = fopen(logf_ce.u.string, "a");
		if (!logfile)
			sigterm_handler(signal);
	}

	ulogd_log(ULOGD_NOTICE, "sighup received, calling plugin handlers\n");
	
	for (p = ulogd_outputs; p; p = p->next) {
		if (p->signal)
			(*p->signal)(SIGHUP);
	}
}

static void print_usage(void)
{
	/* FIXME */
	printf("ulogd Version %s\n", ULOGD_VERSION);
	printf("Copyright (C) 2000-2005 Harald Welte "
	       "<laforge@gnumonks.org>\n");
	printf("This is free software with ABSOLUTELY NO WARRANTY.\n\n");
	printf("Parameters:\n");
	printf("\t-h --help\tThis help page\n");
	printf("\t-V --version\tPrint version information\n");
	printf("\t-d --daemon\tDaemonize (fork into background)\n");
	printf("\t-c --configfile\tUse alternative Configfile\n");
	printf("\t-u --uid\tChange UID/GID\n");
}

static struct option opts[] = {
	{ "version", 0, NULL, 'V' },
	{ "daemon", 0, NULL, 'd' },
	{ "help", 0, NULL, 'h' },
	{ "configfile", 1, NULL, 'c'},
	{ "uid", 1, NULL, 'u' },
	{ 0 }
};

int main(int argc, char* argv[])
{
	int len;
	int argch;
	int daemonize = 0;
	int change_uid = 0;
	char *user = NULL;
	struct passwd *pw;
	uid_t uid = 0;
	gid_t gid = 0;
	ulog_packet_msg_t *upkt;
	ulog_output_t *p;


	while ((argch = getopt_long(argc, argv, "c:dh::Vu:", opts, NULL)) != -1) {
		switch (argch) {
		default:
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);

			print_usage();
			exit(1);
			break;
		case 'h':
			print_usage();
			exit(0);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'V':
			printf("ulogd Version %s\n", ULOGD_VERSION);
			printf("Copyright (C) 2000-2005 Harald Welte "
			       "<laforge@gnumonks.org>\n");
			exit(0);
			break;
		case 'c':
			ulogd_configfile = optarg;
			break;
		case 'u':
			change_uid = 1;
			user = strdup(optarg);
			pw = getpwnam(user);
			if (!pw) {
				printf("Unknown user %s.\n", user);
				free(user);
				exit(1);
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		}
	}

	if (config_register_file(ulogd_configfile)) {
		ulogd_log(ULOGD_FATAL, "error registering configfile \"%s\"\n",
			  ulogd_configfile);
		exit(1);
	}
	
	/* parse config file */
	if (parse_conffile("global", &rmem_ce)) {
		ulogd_log(ULOGD_FATAL, "parse_conffile\n");
		exit(1);
	}

	/* allocate a receive buffer */
	libulog_buf = (unsigned char *) malloc(bufsiz_ce.u.value);

	if (!libulog_buf) {
		ulogd_log(ULOGD_FATAL, "unable to allocate receive buffer"
			  "of %d bytes\n", bufsiz_ce.u.value);
		ipulog_perror(NULL);
		exit(1);
	}

	/* create ipulog handle */
	libulog_h = ipulog_create_handle(ipulog_group2gmask(nlgroup_ce.u.value),
					 rmem_ce.u.value);

	if (!libulog_h) {
		/* if some error occurrs, print it to stderr */
		ulogd_log(ULOGD_FATAL, "unable to create ipulogd handle\n");
		ipulog_perror(NULL);
		exit(1);
	}


	if (change_uid) {
		ulogd_log(ULOGD_NOTICE, "Changing UID / GID\n");
		if (setgid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set GID\n");
			ipulog_perror(NULL);
			exit(1);
		}
		if (setegid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't sett effective GID\n");
			ipulog_perror(NULL);
			exit(1);
		}
		if (initgroups(user, gid)) {
			ulogd_log(ULOGD_FATAL, "can't set user secondary GID\n");
			ipulog_perror(NULL);
			exit(1);
		}
		if (setuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set UID\n");
			ipulog_perror(NULL);
			exit(1);
		}
		if (seteuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective UID\n");
			ipulog_perror(NULL);
			exit(1);
		}
	}

	logfile_open(logf_ce.u.string);

	for (p = ulogd_outputs; p; p = p->next) {
		if (p->init)
			(*p->init)();
	}

#ifdef DEBUG
	/* dump key and interpreter hash */
	interh_dump();
	keyh_dump();
#endif
	if (daemonize){
		if (fork()) {
			exit(0);
		}
		if (logfile != stdout)
			fclose(stdout);
		fclose(stderr);
		fclose(stdin);
		setsid();
	}

	/* send SIGINT to the term handler, since they hit CTRL-C */
	signal(SIGINT, &sigterm_handler);
	signal(SIGHUP, &sighup_handler);
	signal(SIGTERM, &sigterm_handler);

	ulogd_log(ULOGD_NOTICE, 
		  "initialization finished, entering main loop\n");

	/* endless loop receiving packets and handling them over to
	 * handle_packet */
	while ((len = ipulog_read(libulog_h, libulog_buf, 
				 bufsiz_ce.u.value, 1))) {

		if (len <= 0) {
			/* this is not supposed to happen */
			ulogd_log(ULOGD_ERROR, "ipulog_read == %d! "
				  "ipulog_errno == %d, errno = %d\n",
				  len, ipulog_errno, errno);
		} else {
			while ((upkt = ipulog_get_packet(libulog_h,
					       libulog_buf, len))) {
				DEBUGP("==> packet received\n");
				handle_packet(upkt);
			}
		}
	}

	/* hackish, but result is the same */
	sigterm_handler(SIGTERM);	
	return(0);
}
