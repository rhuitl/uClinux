/* ulogd, Version $LastChangedRevision: 6383 $
 *
 * $Id: ulogd.c 6383 2006-01-08 23:06:26Z /C=DE/ST=Berlin/L=Berlin/O=Netfilter Project/OU=Development/CN=laforge/emailAddress=laforge@netfilter.org $
 *
 * unified network logging daemon for Linux.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 *
 * 	22 Jul 2004 Harald Welte <laforge@gnumonks.org>
 * 		- major restructuring for flow accounting / ipfix work
 *
 * 	03 Oct 2004 Harald Welte <laforge@gnumonks.org>
 * 		- further unification towards generic network event logging
 * 		  and support for lnstat
 *
 * 	07 Oct 2005 Harald Welte <laforge@gnumonks.org>
 * 		- finally get ulogd2 into a running state
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
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
#include <ulogd/conffile.h>
#include <ulogd/ulogd.h>
#ifdef DEBUG
#define DEBUGP(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGP(format, args...) 
#endif

#define COPYRIGHT \
	"Copyright (C) 2000-2005 Harald Welte <laforge@netfilter.org>\n"

#define LOGFILE_STDERR 0
#define LOGFILE_STDOUT 1
#define LOGFILE_SYSLOG 2
#define LOGFILE_FILE   3

/* global variables */
static int logfile_type = LOGFILE_STDERR;
static FILE *logfile = NULL;		/* logfile pointer */
static char *ulogd_configfile = ULOGD_CONFIGFILE;

/* linked list for all registered plugins */
static LLIST_HEAD(ulogd_plugins);
static LLIST_HEAD(ulogd_pi_stacks);


static int load_plugin(const char *file);
static int create_stack(const char *file);
static int logfile_open(const char *name);

static struct config_keyset ulogd_kset = {
	.num_ces = 4,
	.ces = {
		{
			.key = "logfile",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_NONE,
			.u.parser = &logfile_open,
		},
		{
			.key = "plugin",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_MULTI,
			.u.parser = &load_plugin,
		},
		{
			.key = "loglevel", 
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = ULOGD_NOTICE,
		},
		{
			.key = "stack",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_MULTI,
			.u.parser = &create_stack,
		},
	},
};

#define logfile_ce	ulogd_kset.ces[0]
#define plugin_ce	ulogd_kset.ces[1]
#define loglevel_ce	ulogd_kset.ces[2]
#define stack_ce	ulogd_kset.ces[3]

/***********************************************************************
 * UTILITY FUNCTIONS FOR PLUGINS
 ***********************************************************************/

int ulogd_key_size(struct ulogd_key *key)
{
	int ret;

	switch (key->type) {
	case ULOGD_RET_INT8:
	case ULOGD_RET_UINT8:
	case ULOGD_RET_BOOL:
		ret = 1;
		break;
	case ULOGD_RET_INT16:
	case ULOGD_RET_UINT16:
		ret = 2;
		break;
	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT32:
	case ULOGD_RET_IPADDR:
		ret = 4;
		break;
	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		ret = 8;
		break;
	case ULOGD_RET_IP6ADDR:
		ret = 16;
		break;
	case ULOGD_RET_STRING:
		ret = strlen(key->u.value.ptr);
		break;
	case ULOGD_RET_RAW:
		ret = key->len;
		break;
	default:
		ulogd_log(ULOGD_ERROR, "don't know sizeo f unknown key "
			  "`%s' type 0x%x\n", key->name, key->type);
		ret = -1;
		break;
	}

	return ret;
}

int ulogd_wildcard_inputkeys(struct ulogd_pluginstance *upi)
{
	struct ulogd_pluginstance_stack *stack = upi->stack;
	struct ulogd_pluginstance *pi_cur;
	unsigned int num_keys = 0;
	unsigned int index = 0;

	/* ok, this is a bit tricky, and probably requires some documentation.
	 * Since we are a output plugin (SINK), we can only be the last one
	 * in the stack.  Therefore, all other (input/filter) plugins, area
	 * already linked into the stack.  This means, we can iterate over them,
	 * get a list of all the keys, and create one input key for every output
	 * key that any of the upstream plugins provide.  By the time we resolve
	 * the inter-key pointers, everything will work as expected. */

	if (upi->input.keys)
		free(upi->input.keys);

	/* first pass: count keys */
	llist_for_each_entry(pi_cur, &stack->list, list) {
		ulogd_log(ULOGD_DEBUG, "iterating over pluginstance '%s'\n",
			  pi_cur->id);
		num_keys += pi_cur->plugin->output.num_keys;
	}

	ulogd_log(ULOGD_DEBUG, "allocating %u input keys\n", num_keys);
	upi->input.keys = malloc(sizeof(struct ulogd_key) * num_keys);
	if (!upi->input.keys)
		return -ENOMEM;

	/* second pass: copy key names */
	llist_for_each_entry(pi_cur, &stack->list, list) {
		struct ulogd_key *cur;
		int i;

		for (i = 0; i < pi_cur->plugin->output.num_keys; i++)
			upi->input.keys[index++] = pi_cur->output.keys[i];
	}

	upi->input.num_keys = num_keys;

	return 0;
}


/***********************************************************************
 * PLUGIN MANAGEMENT 
 ***********************************************************************/

/* try to lookup a registered plugin for a given name */
static struct ulogd_plugin *find_plugin(const char *name)
{
	struct ulogd_plugin *pl;

	llist_for_each_entry(pl, &ulogd_plugins, list) {
		if (strcmp(name, pl->name) == 0)
			return pl;
	}

	return NULL;
}

/* the function called by all plugins for registering themselves */
void ulogd_register_plugin(struct ulogd_plugin *me)
{
	if (strcmp(me->version, ULOGD_VERSION)) { 
		ulogd_log(ULOGD_NOTICE, "plugin `%s' has incompatible version %s\n",
			  me->version);
		return;
	}
	if (find_plugin(me->name)) {
		ulogd_log(ULOGD_NOTICE, "plugin `%s' already registered\n",
				me->name);
		exit(EXIT_FAILURE);
	}
	ulogd_log(ULOGD_NOTICE, "registering plugin `%s'\n", me->name);
	llist_add(&me->list, &ulogd_plugins);
}

/***********************************************************************
 * MAIN PROGRAM
 ***********************************************************************/

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
	if (level < loglevel_ce.u.value)
		return;

	if (logfile_type == LOGFILE_SYSLOG) {
		/* FIXME: this omits the 'file' string */
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

/* clean results (set all values to 0 and free pointers) */
static void ulogd_clean_results(struct ulogd_pluginstance *pi)
{
	struct ulogd_pluginstance *cur;

	DEBUGP("cleaning up results\n");

	/* iterate through plugin stack */
	llist_for_each_entry(cur, &pi->stack->list, list) {
		int i;
		
		/* iterate through input keys of pluginstance */
		for (i = 0; i < cur->output.num_keys; i++) {
			struct ulogd_key *key = &cur->output.keys[i];

			if (!(key->flags & ULOGD_RETF_VALID))
				continue;

			if (key->flags & ULOGD_RETF_FREE) {
				free(key->u.value.ptr);
				key->u.value.ptr = NULL;
			}
			memset(&key->u.value, 0, sizeof(key->u.value));
			key->flags &= ~ULOGD_RETF_VALID;
		}
	}
}

/* propagate results to all downstream plugins in the stack */
void ulogd_propagate_results(struct ulogd_pluginstance *pi)
{
	struct ulogd_pluginstance *cur = pi;
	/* iterate over remaining plugin stack */
	llist_for_each_entry_continue(cur, &pi->stack->list, list) {
		int ret;
		
		ret = cur->plugin->interp(cur);
		switch (ret) {
		case ULOGD_IRET_ERR:
			ulogd_log(ULOGD_NOTICE,
				  "error during propagate_results\n");
			/* fallthrough */
		case ULOGD_IRET_STOP:
			/* we shall abort further iteration of the stack */
			break;
		case ULOGD_IRET_OK:
			/* we shall continue travelling down the stack */
			continue;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "unknown return value `%d' from plugin %s\n",
				  ret, cur->plugin->name);
			break;
		}
	}

	ulogd_clean_results(pi);
}

static struct ulogd_pluginstance *
pluginstance_alloc_init(struct ulogd_plugin *pl, char *pi_id,
			struct ulogd_pluginstance_stack *stack)
{
	unsigned int size;
	struct ulogd_pluginstance *pi;
	void *ptr;

	size = sizeof(struct ulogd_pluginstance);
	size += pl->priv_size;
	if (pl->config_kset) {
		size += sizeof(struct config_keyset);
		if (pl->config_kset->num_ces)
			size += pl->config_kset->num_ces * 
						sizeof(struct config_entry);
	}
	size += pl->input.num_keys * sizeof(struct ulogd_key);
	size += pl->output.num_keys * sizeof(struct ulogd_key);
	pi = malloc(size);
	if (!pi)
		return NULL;

	/* initialize */
	memset(pi, 0, size);
	INIT_LLIST_HEAD(&pi->list);
	pi->plugin = pl;
	pi->stack = stack;
	memcpy(pi->id, pi_id, sizeof(pi->id));

	ptr = (void *)pi + sizeof(*pi);

	ptr += pl->priv_size;
	/* copy config keys */
	if (pl->config_kset) {
		pi->config_kset = ptr;
		ptr += sizeof(struct config_keyset);
		pi->config_kset->num_ces = pl->config_kset->num_ces;
		if (pi->config_kset->num_ces) {
			ptr += pi->config_kset->num_ces 
						* sizeof(struct config_entry);
			memcpy(pi->config_kset->ces, pl->config_kset->ces, 
			       pi->config_kset->num_ces 
			       			*sizeof(struct config_entry));
		}
	} else
		pi->config_kset = NULL;

	/* copy input keys */
	if (pl->input.num_keys) {
		pi->input.num_keys = pl->input.num_keys;
		pi->input.keys = ptr;
		memcpy(pi->input.keys, pl->input.keys, 
		       pl->input.num_keys * sizeof(struct ulogd_key));
		ptr += pl->input.num_keys * sizeof(struct ulogd_key);
	}
	
	/* copy input keys */
	if (pl->output.num_keys) {
		pi->output.num_keys = pl->output.num_keys;
		pi->output.keys = ptr;
		memcpy(pi->output.keys, pl->output.keys, 
		       pl->output.num_keys * sizeof(struct ulogd_key));
	}

	return pi;
}


/* plugin loader to dlopen() a plugins */
static int load_plugin(const char *file)
{
	if (!dlopen(file, RTLD_NOW)) {
		ulogd_log(ULOGD_ERROR, "load_plugin: '%s': %s\n", file,
			  dlerror());
		return -1;
	}
	return 0;
}

/* find an output key in a given stack, starting at 'start' */
static struct ulogd_key *
find_okey_in_stack(char *name,
		   struct ulogd_pluginstance_stack *stack,
		   struct ulogd_pluginstance *start)
{
	struct ulogd_pluginstance *pi;

	llist_for_each_entry_reverse(pi, &start->list, list) {
		int i;

		if ((void *)&pi->list == &stack->list)
			return NULL;

		for (i = 0; i < pi->output.num_keys; i++) {
			struct ulogd_key *okey = &pi->output.keys[i];
			if (!strcmp(name, okey->name)) {
				ulogd_log(ULOGD_DEBUG, "%s(%s)\n",
					  pi->id, pi->plugin->name);
				return okey;
			}
		}
	}

	return NULL;
}

/* resolve key connections from bottom to top of stack */
static int
create_stack_resolve_keys(struct ulogd_pluginstance_stack *stack)
{
	int i = 0;
	struct ulogd_pluginstance *pi_cur;

	/* PASS 2: */
	ulogd_log(ULOGD_DEBUG, "connecting input/output keys of stack:\n");
	llist_for_each_entry_reverse(pi_cur, &stack->list, list) {
		struct ulogd_pluginstance *pi_prev = 
					llist_entry(pi_cur->list.prev,
						   struct ulogd_pluginstance,
						   list);
		i++;
		ulogd_log(ULOGD_DEBUG, "traversing plugin `%s'\n", 
			  pi_cur->plugin->name);
		/* call plugin to tell us which keys it requires in
		 * given configuration */
		if (pi_cur->plugin->configure) {
			int ret = pi_cur->plugin->configure(pi_cur, 
							    stack);
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "error during "
					  "configure of plugin %s\n",
					  pi_cur->plugin->name);
				return ret;
			}
		}

		if (i == 1) {
			/* first round: output plugin */
			if (!(pi_cur->plugin->output.type & ULOGD_DTYPE_SINK)) {
				ulogd_log(ULOGD_ERROR, "last plugin in stack "
					  "has to be output plugin\n");
				return -EINVAL;
			}
			/* continue further down */
		} /* no "else' since first could be the last one, too ! */

		if (&pi_prev->list == &stack->list) {
			/* this is the last one in the stack */
			if (!(pi_cur->plugin->input.type 
						& ULOGD_DTYPE_SOURCE)) {
				ulogd_log(ULOGD_ERROR, "first plugin in stack "
					  "has to be source plugin\n");
				return -EINVAL;
			}
			/* no need to match keys */
		} else {
			int j;

			/* not the last one in the stack */
			if (!(pi_cur->plugin->input.type &
					pi_prev->plugin->output.type)) {
				ulogd_log(ULOGD_ERROR, "type mismatch between "
					  "%s and %s in stack\n",
					  pi_cur->plugin->name,
					  pi_prev->plugin->name);
			}
	
			for (j = 0; j < pi_cur->input.num_keys; j++) {
				struct ulogd_key *okey;
				struct ulogd_key *ikey = &pi_cur->input.keys[j];

				/* skip those marked as 'inactive' by
				 * pl->configure() */
				if (ikey->flags & ULOGD_KEYF_INACTIVE)
					continue;

				if (ikey->u.source) { 
					ulogd_log(ULOGD_ERROR, "input key `%s' "
						  "already has source\n",
						  ikey->name);

					return -EINVAL;
				}

				okey = find_okey_in_stack(ikey->name, 
							  stack, pi_cur);
				if (!okey) {
					if (ikey->flags & ULOGD_KEYF_OPTIONAL)
						continue;
					ulogd_log(ULOGD_ERROR, "cannot find "
						  "key `%s' in stack\n",
						  ikey->name);
					return -EINVAL;
				}

				ulogd_log(ULOGD_DEBUG, "assigning `%s(?)' as "
					  "source for %s(%s)\n", okey->name,
					  pi_cur->plugin->name, ikey->name);
				ikey->u.source = okey;
			}
		}
	}

	return 0;
}

static int create_stack_start_instances(struct ulogd_pluginstance_stack *stack)
{
	int ret;
	struct ulogd_pluginstance *pi;

	/* start from input to output plugin */
	llist_for_each_entry(pi, &stack->list, list) {
		if (!pi->plugin->start)
			continue;

		ret = pi->plugin->start(pi);
		if (ret < 0) {
			ulogd_log(ULOGD_ERROR, "error during start of `%s'\n",
				  pi->id);
			return ret;
		}
	}
	return 0;
}

/* create a new stack of plugins */
static int create_stack(const char *option)
{
	struct ulogd_pluginstance_stack *stack;
	char *buf = strdup(option);
	char *tok;
	int ret;

	if (!buf) {
		ulogd_log(ULOGD_ERROR, "");
		ret = -ENOMEM;
		goto out_buf;
	}

	stack = malloc(sizeof(*stack));
	if (!stack) {
		ret = -ENOMEM;
		goto out_stack;
	}
	INIT_LLIST_HEAD(&stack->list);

	ulogd_log(ULOGD_DEBUG, "building new pluginstance stack (%s):\n",
		  option);

	/* PASS 1: find and instanciate plugins of stack, link them together */
	for (tok = strtok(buf, ",\n"); tok; tok = strtok(NULL, ",\n")) {
		char *plname, *equals;
		char pi_id[ULOGD_MAX_KEYLEN];
		struct ulogd_pluginstance *pi;
		struct ulogd_plugin *pl;

		ulogd_log(ULOGD_DEBUG, "tok=`%s'\n", tok);

		/* parse token into sub-tokens */
		equals = strchr(tok, ':');
		if (!equals || (equals - tok >= ULOGD_MAX_KEYLEN)) {
			ulogd_log(ULOGD_ERROR, "syntax error while parsing `%s'"
				  "of line `%s'\n", tok, buf);
			ret = -EINVAL;
			goto out;
		}
		strncpy(pi_id, tok, ULOGD_MAX_KEYLEN-1);
		pi_id[equals-tok] = '\0';
		plname = equals+1;
	
		/* find matching plugin */
 		pl = find_plugin(plname);
		if (!pl) {
			ulogd_log(ULOGD_ERROR, "can't find requested plugin "
				  "%s\n", plname);
			ret = -ENODEV;
			goto out;
		}

		/* allocate */
		pi = pluginstance_alloc_init(pl, pi_id, stack);
		if (!pi) {
			ulogd_log(ULOGD_ERROR, 
				  "unable to allocate pluginstance for %s\n",
				  pi_id);
			ret = -ENOMEM;
			goto out;
		}
	
		/* FIXME: call constructor routine from end to beginning,
		 * fix up input/output keys */
			
		ulogd_log(ULOGD_DEBUG, "pushing `%s' on stack\n", pl->name);
		llist_add_tail(&pi->list, &stack->list);
	}

	/* PASS 2: resolve key connections from bottom to top of stack */
	ret = create_stack_resolve_keys(stack);
	if (ret < 0) {
		ulogd_log(ULOGD_DEBUG, "destroying stack\n");
		goto out;
	}

	/* PASS 3: start each plugin in stack */
	ret = create_stack_start_instances(stack);
	if (ret < 0) {
		ulogd_log(ULOGD_DEBUG, "destroying stack\n");
		goto out;
	}

	/* add head of pluginstance stack to list of stacks */
	llist_add(&stack->stack_list, &ulogd_pi_stacks);
	free(buf);
	return 0;

out:
	free(stack);
out_stack:
	free(buf);
out_buf:
	return ret;
}
	

static int ulogd_main_loop(void)
{
	int ret = 0;

	while (1) {
		ret = ulogd_select_main();
		if (ret == 0) 
			continue;

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			else {
				ulogd_log(ULOGD_ERROR, "select returned %s\n",
					  strerror(errno));
				break;
			}
		}
	}

	return ret;
}

/* open the logfile */
static int logfile_open(const char *name)
{
	if (!strcmp(name, "stdout")) {
		logfile_type = LOGFILE_STDOUT;
		logfile = stdout;
	} else if (!strcmp(name, "syslog")) {
		logfile_type = LOGFILE_SYSLOG;
	        openlog("ulogd", LOG_NDELAY|LOG_PID, LOG_DAEMON);
	} else if (strlen(name) < CONFIG_VAL_STRING_LEN ) {
		/* FIXME: what if not ? */
		logfile_type = LOGFILE_FILE;
		strcpy(logfile_ce.u.string, name);
		logfile = fopen(logfile_ce.u.string, "a");
		if (!logfile) {
			fprintf(stderr, "ERROR: can't open logfile %s: %s\n", 
				logfile_ce.u.string, strerror(errno));
			exit(2);
		}
	}
	ulogd_log(ULOGD_INFO, "ulogd Version %s starting\n", ULOGD_VERSION);
	return 0;
}

/* wrapper to handle conffile error codes */
static int parse_conffile(const char *section, struct config_keyset *ce)
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

static void deliver_signal_pluginstances(int signal)
{
	struct ulogd_pluginstance_stack *stack;
	struct ulogd_pluginstance *pi;

	llist_for_each_entry(stack, &ulogd_pi_stacks, stack_list) {
		llist_for_each_entry(pi, &stack->list, list) {
			if (pi->plugin->signal)
				(*pi->plugin->signal)(pi, signal);
		}
	}
}

static void sigterm_handler(int signal)
{
	
	ulogd_log(ULOGD_NOTICE, "sigterm received, exiting\n");

	deliver_signal_pluginstances(signal);

	if (logfile_type == LOGFILE_FILE)
		fclose(logfile);

	exit(0);
}

static void signal_handler(int signal)
{
	ulogd_log(ULOGD_NOTICE, "signal received, calling pluginstances\n");
	
	switch (signal) {
	case SIGHUP:
		/* reopen logfile */
		if (logfile_type == LOGFILE_FILE) {
			fclose(logfile);
			logfile = fopen(logfile_ce.u.string, "a");
			if (!logfile)
				sigterm_handler(signal);
		}
		break;
	case SIGALRM:
		ulogd_timer_check_n_run();
		break;
	default:
		break;
	}

	deliver_signal_pluginstances(signal);
}

static void print_usage(void)
{
	/* FIXME */
	printf("ulogd Version %s\n", ULOGD_VERSION);
	printf(COPYRIGHT);
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
	int argch;
	int daemonize = 0;
	int change_uid = 0;
	char *user = NULL;
	struct passwd *pw;
	uid_t uid = 0;
	gid_t gid = 0;


	while ((argch = getopt_long(argc, argv, "c:dh::Vu:", opts, NULL)) != -1) {
		switch (argch) {
		default:
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", 
					optopt);
			else
				fprintf(stderr, "Unknown option character "
					"`\\x%x'.\n", optopt);

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
			printf(COPYRIGHT);
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
	if (parse_conffile("global", &ulogd_kset)) {
		ulogd_log(ULOGD_FATAL, "parse_conffile\n");
		exit(1);
	}

	if (llist_empty(&ulogd_pi_stacks)) {
		ulogd_log(ULOGD_FATAL, 
			  "not even a single working plugin stack\n");
		exit(1);
	}

	if (change_uid) {
		ulogd_log(ULOGD_NOTICE, "Changing UID / GID\n");
		if (setgid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set GID %u\n", gid);
			exit(1);
		}
		if (setegid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't sett effective GID %u\n",
				  gid);
			exit(1);
		}
		if (initgroups(user, gid)) {
			ulogd_log(ULOGD_FATAL, "can't set user secondary GID\n");
			exit(1);
		}
		if (setuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set UID %u\n", uid);
			exit(1);
		}
		if (seteuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective UID %u\n",
				  uid);
			exit(1);
		}
	}

	if (daemonize){
		if (fork()) {
			exit(0);
		}
		if (logfile_type != LOGFILE_STDOUT)
			fclose(stdout);
		fclose(stderr);
		fclose(stdin);
		setsid();
	}

	signal(SIGTERM, &sigterm_handler);
	signal(SIGHUP, &signal_handler);
	signal(SIGALRM, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);

	ulogd_log(ULOGD_INFO, 
		  "initialization finished, entering main loop\n");

	ulogd_main_loop();

	/* hackish, but result is the same */
	sigterm_handler(SIGTERM);	
	return(0);
}
