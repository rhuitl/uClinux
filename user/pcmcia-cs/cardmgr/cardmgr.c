/*======================================================================

    PCMCIA Card Manager daemon

    cardmgr.c 1.159 2001/06/22 04:17:17

    The contents of this file are subject to the Mozilla Public
    License Version 1.1 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a copy of
    the License at http://www.mozilla.org/MPL/

    Software distributed under the License is distributed on an "AS
    IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
    implied. See the License for the specific language governing
    rights and limitations under the License.

    The initial developer of the original code is David A. Hinds
    <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
    are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.

    Alternatively, the contents of this file may be used under the
    terms of the GNU Public License version 2 (the "GPL"), in which
    case the provisions of the GPL are applicable instead of the
    above.  If you wish to allow the use of your version of this file
    only under the terms of the GPL and not to allow others to use
    your version of this file under the MPL, indicate your decision
    by deleting the provisions above and replace them with the notice
    and other provisions required by the GPL.  If you do not delete
    the provisions above, a recipient may use your version of this
    file under either the MPL or the GPL.
    
======================================================================*/

#ifndef __linux__
#include <pcmcia/u_compat.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/file.h>

#include <pcmcia/version.h>
#include <pcmcia/config.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ds.h>

#include "cardmgr.h"

/*====================================================================*/

typedef struct socket_info_t {
    int			fd;
    int			state;
    card_info_t		*card;
    bind_info_t		*bind[MAX_BINDINGS];
    mtd_ident_t		*mtd[2*CISTPL_MAX_DEVICES];
} socket_info_t;

#define SOCKET_PRESENT	0x01
#define SOCKET_READY	0x02
#define SOCKET_HOTPLUG	0x04

/* Linked list of resource adjustments */
struct adjust_list_t *root_adjust = NULL;

/* Linked list of device definitions */
struct device_info_t *root_device = NULL;

/* Special pointer to "anonymous" card definition */
struct card_info_t *blank_card = NULL;

/* Linked list of card definitions */
struct card_info_t *root_card = NULL;

/* Linked list of function definitions */
struct card_info_t *root_func = NULL;

/* Linked list of MTD definitions */
struct mtd_ident_t *root_mtd = NULL;

/* Default MTD */
struct mtd_ident_t *default_mtd = NULL;

static int sockets;
static struct socket_info_t socket[MAX_SOCKS];

/* Default path for config file, device scripts */
#ifdef ETC
static char *configpath = ETC;
#else
static char *configpath = "/etc/pcmcia";
#endif

/* Default path for pid file */
static char *pidfile = "/var/run/cardmgr.pid";

#ifdef __linux__
/* Default path for finding modules */
static char *modpath = NULL;
#endif

/* Default path for socket info table */
static char *stabfile;

/* If set, don't generate beeps when cards are inserted */
static int be_quiet = 0;

/* If set, use modprobe instead of insmod */
static int do_modprobe = 0;

/* If set, configure already inserted cards, then exit */
static int one_pass = 0;

/* Extra message logging? */
static int verbose = 0;

/*====================================================================*/

#ifdef __linux__

static int major = 0;

static int lookup_dev(char *name)
{
    FILE *f;
    int n;
    char s[32], t[32];
    
    f = fopen("/proc/devices", "r");
    if (f == NULL)
	return -errno;
    while (fgets(s, 32, f) != NULL) {
	if (sscanf(s, "%d %s", &n, t) == 2)
	    if (strcmp(name, t) == 0)
		break;
    }
    fclose(f);
    if (strcmp(name, t) == 0)
	return n;
    else
	return -ENODEV;
}

int open_dev(dev_t dev, int mode)
{
    static char *paths[] = {
	"/var/lib/pcmcia", "/var/run", "/dev", "/tmp", NULL
    };
    char **p, fn[64];
    int fd;

    for (p = paths; *p; p++) {
	sprintf(fn, "%s/cm-%d", *p, getpid());
	if (mknod(fn, mode, dev) == 0)
	    break;
    }
    if (!*p)
	return -1;
    fd = open(fn, (mode&S_IWRITE)?O_RDWR:O_RDONLY);
    if (fd < 0)
	fd = open(fn, O_NONBLOCK|((mode&S_IWRITE)?O_RDWR:O_RDONLY));
    unlink(fn);
    return fd;
}

#endif /* __linux__ */

int open_sock(int sock, int mode)
{
#ifdef __linux__
    dev_t dev = (major<<8)+sock;
    return open_dev(dev, mode);
#endif
#ifdef __BEOS__
    int fd;
    char fn[B_OS_NAME_LENGTH];
    sprintf(fn, "/dev/pcmcia/sock%d", sock);
    return open(fn, (mode & S_IWRITE) ? O_RDWR: O_RDONLY);
#endif
}

/*======================================================================

    xlate_scsi_name() is a sort-of-hack used to deduce the minor
    device numbers of SCSI devices, from the information available to
    the low-level driver.
    
======================================================================*/

/* getting these from headers is too much grief */
#define SCSI_DISK0_MAJOR    8
#define SCSI_TAPE_MAJOR     9
#define SCSI_CDROM_MAJOR    11
#define SCSI_GENERIC_MAJOR  21
#define SCSI_IOCTL_GET_IDLUN    0x5382

static int xlate_scsi_name(bind_info_t *bind)
{
    int i, fd, mode, minor;
    u_long arg[2], id1, id2;

    id1 = strtol(bind->name+3, NULL, 16);
    if ((bind->major == SCSI_DISK0_MAJOR) ||
	(bind->major == SCSI_CDROM_MAJOR))
	mode = S_IREAD|S_IFBLK;
    else
	mode = S_IREAD|S_IFCHR;
    
    for (i = 0; i < 16; i++) {
	minor = (bind->major == SCSI_DISK0_MAJOR) ? (i<<4) : i;
	fd = open_dev((bind->major<<8)+minor, mode);
	if (fd < 0)
	    continue;
	if (ioctl(fd, SCSI_IOCTL_GET_IDLUN, arg) == 0) {
	    id2 = (arg[0]&0x0f) + ((arg[0]>>4)&0xf0) +
		((arg[0]>>8)&0xf00) + ((arg[0]>>12)&0xf000);
	    if (id1 == id2) {
		close(fd);
		switch (bind->major) {
		case SCSI_DISK0_MAJOR:
		case SCSI_GENERIC_MAJOR:
		    sprintf(bind->name+2, "%c", 'a'+i); break;
		case SCSI_CDROM_MAJOR:
		    sprintf(bind->name, "scd%d", i); break;
		case SCSI_TAPE_MAJOR:
		    sprintf(bind->name+2, "%d", i); break;
		}
		bind->minor = minor;
		return 0;
	    }
	}
	close(fd);
    }
    return -1;
}

/*====================================================================*/

#define BEEP_TIME 150
#define BEEP_OK   1000
#define BEEP_WARN 2000
#define BEEP_ERR  4000

#ifdef __linux__

#include <sys/kd.h>

static void beep(unsigned int ms, unsigned int freq)
{
    int fd, arg;

    if (be_quiet)
	return;
    fd = open("/dev/console", O_RDWR);
    if (fd < 0)
	return;
    arg = (ms << 16) | freq;
    ioctl(fd, KDMKTONE, arg);
    close(fd);
    usleep(ms*1000);
}

#endif /* __linux__ */

#ifdef __BEOS__
static void beep(unsigned int ms, unsigned int freq)
{
    if (!be_quiet) system("/bin/beep");
}
#endif

/*====================================================================*/

static void write_pid(void)
{
    FILE *f;
    f = fopen(pidfile, "w");
    if (f == NULL)
	syslog(LOG_WARNING, "could not open %s: %m", pidfile);
    else {
	fprintf(f, "%d\n", getpid());
	fclose(f);
    }
}

static void write_stab(void)
{
    int i, j, k;
    FILE *f;
    socket_info_t *s;
    bind_info_t *bind;

    f = fopen(stabfile, "w");
    if (f == NULL) {
	syslog(LOG_WARNING, "fopen(stabfile) failed: %m");
	return;
    }
#ifndef __BEOS__
    if (flock(fileno(f), LOCK_EX) != 0) {
	syslog(LOG_ERR, "flock(stabfile) failed: %m");
	return;
    }
#endif
    for (i = 0; i < sockets; i++) {
	s = &socket[i];
	if (!(s->state & SOCKET_PRESENT))
	    fprintf(f, "Socket %d: empty\n", i);
	else if (!s->card)
	    fprintf(f, "Socket %d: unsupported card\n", i);
	else {
	    fprintf(f, "Socket %d: %s\n", i, s->card->name);
	    for (j = 0; j < s->card->bindings; j++)
		for (k = 0, bind = s->bind[j];
		     bind != NULL;
		     k++, bind = bind->next) {
		    char *class = s->card->device[j]->class;
		    fprintf(f, "%d\t%s\t%s\t%d\t%s",
			    i, (class ? class : "none"),
			    bind->dev_info, k, bind->name);
		    if (bind->major)
			fprintf(f, "\t%d\t%d\n",
				bind->major, bind->minor);
		    else
			fputc('\n', f);
		}
	}
    }
    fflush(f);
#ifndef __BEOS__
    flock(fileno(f), LOCK_UN);
#endif
    fclose(f);
}

/*====================================================================*/

static int get_tuple(int ns, cisdata_t code, ds_ioctl_arg_t *arg)
{
    socket_info_t *s = &socket[ns];
    
    arg->tuple.DesiredTuple = code;
    arg->tuple.Attributes = 0;
    if (ioctl(s->fd, DS_GET_FIRST_TUPLE, arg) != 0)
	return -1;
    arg->tuple.TupleOffset = 0;
    if (ioctl(s->fd, DS_GET_TUPLE_DATA, arg) != 0) {
	syslog(LOG_INFO, "error reading CIS data on socket %d: %m", ns);
	return -1;
    }
    if (ioctl(s->fd, DS_PARSE_TUPLE, arg) != 0) {
	syslog(LOG_INFO, "error parsing CIS on socket %d: %m", ns);
	return -1;
    }
    return 0;
}

/*======================================================================

    Code to fetch a 2.4 kernel's hot plug PCI driver list

    This is distasteful but is the best I could come up with.

======================================================================*/

#ifdef __linux__

typedef struct pci_id {
    u_short vendor, device;
    struct pci_id *next;
} pci_id_t;

pci_id_t *hotplug_list = NULL;

static void load_pcimap(void)
{
    char s[133], *fn = malloc(strlen(modpath) + 20);
    int v, d;
    FILE *f;

    strcpy(fn, modpath);
    strcat(fn, "/modules.pcimap");
    f = fopen(fn, "r");
    if (!f) return;

    while (fgets(s, 132, f) != NULL) {
	if (sscanf(s, "%*s %x %x", &v, &d) == 2) {
	    pci_id_t *e = malloc(sizeof *e);
	    e->vendor = v; e->device = d;
	    e->next = hotplug_list;
	    hotplug_list = e;
	}
    }
    fclose(f);
}

static int get_pci_id(int ns, pci_id_t *id)
{
    socket_info_t *s = &socket[ns];
    config_info_t config;
    unsigned char *bp;
    char fn[50];
    int fd;

    config.Function = config.ConfigBase = 0;
    if ((ioctl(s->fd, DS_GET_CONFIGURATION_INFO, &config) != 0) ||
	(config.IntType != INT_CARDBUS))
	return 0;
    if (config.ConfigBase) {
	/* this indicates non-hotplug PCMCIA support */
	hotplug_list = NULL;
    } else {
	sprintf(fn, "/proc/bus/pci/%02d/00.0", config.Option);
	if ((fd = open(fn, O_RDONLY)) < 0)
	    return 0;
	read(fd, &config.ConfigBase, 4);
	close(fd);
    }
    bp = (unsigned char *) &config.ConfigBase;
    id->vendor = bp[0] | (bp[1] << 8);
    id->device = bp[2] | (bp[3] << 8);
    return 1;
}

#endif /* __linux__ */

/*====================================================================*/

static void log_card_info(cistpl_vers_1_t *vers,
			  cistpl_manfid_t *manfid,
			  cistpl_funcid_t *funcid,
			  pci_id_t *pci_id)
{
    char v[256] = "";
    int i;
    static char *fn[] = {
	"multi", "memory", "serial", "parallel", "fixed disk",
	"video", "network", "AIMS", "SCSI"
    };
    
    if (vers) {
	for (i = 0; i < vers->ns; i++)
	    sprintf(v+strlen(v), "%s\"%s\"",
		    (i>0) ? ", " : "", vers->str+vers->ofs[i]);
	syslog(LOG_INFO, "  product info: %s", v);
    } else {
	syslog(LOG_INFO, "  no product info available");
    }
    *v = '\0';
    if (manfid->manf != 0)
	sprintf(v, "  manfid: 0x%04x, 0x%04x",
		manfid->manf, manfid->card);
    if (funcid->func != 0xff)
	sprintf(v+strlen(v), "  function: %d (%s)", funcid->func,
		fn[funcid->func]);
    if (strlen(v) > 0) syslog(LOG_INFO, "%s", v);
    if (pci_id->vendor != 0)
	syslog(LOG_INFO, "  PCI id: 0x%04x, 0x%04x",
	       pci_id->vendor, pci_id->device);
}

static card_info_t *lookup_card(int ns)
{
    socket_info_t *s = &socket[ns];
    card_info_t *card = NULL;
    ds_ioctl_arg_t arg;
    cistpl_vers_1_t *vers = NULL;
    cistpl_manfid_t manfid = { 0, 0 };
    pci_id_t pci_id = { 0, 0 };
    cistpl_funcid_t funcid = { 0xff, 0xff };
    cs_status_t status;
    int i, ret, has_cis = 0;

    /* Do we have a CIS structure? */
    ret = ioctl(s->fd, DS_VALIDATE_CIS, &arg);
    has_cis = ((ret == 0) && (arg.cisinfo.Chains > 0));
    
    /* Try to read VERS_1, MANFID tuples */
    if (has_cis) {
	/* rule of thumb: cards with no FUNCID, but with common memory
	   device geometry information, are probably memory cards */
	if (get_tuple(ns, CISTPL_FUNCID, &arg) == 0)
	    memcpy(&funcid, &arg.tuple_parse.parse.funcid,
		   sizeof(funcid));
	else if (get_tuple(ns, CISTPL_DEVICE_GEO, &arg) == 0)
	    funcid.func = CISTPL_FUNCID_MEMORY;
	if (get_tuple(ns, CISTPL_MANFID, &arg) == 0)
	    memcpy(&manfid, &arg.tuple_parse.parse.manfid,
		   sizeof(manfid));
	if (get_tuple(ns, CISTPL_VERS_1, &arg) == 0)
	    vers = &arg.tuple_parse.parse.version_1;

	for (card = root_card; card; card = card->next) {

	    if (card->ident_type &
		~(VERS_1_IDENT|MANFID_IDENT|TUPLE_IDENT))
		continue;

	    if (card->ident_type & VERS_1_IDENT) {
		if (vers == NULL)
		    continue;
		for (i = 0; i < card->id.vers.ns; i++) {
		    if (strcmp(card->id.vers.pi[i], "*") == 0)
			continue;
		    if (i >= vers->ns)
			break;
		    if (strcmp(card->id.vers.pi[i],
			       vers->str+vers->ofs[i]) != 0)
			break;
		}
		if (i < card->id.vers.ns)
		    continue;
	    }
	    
	    if (card->ident_type & MANFID_IDENT) {
		if ((manfid.manf != card->manfid.manf) ||
		    (manfid.card != card->manfid.card))
		    continue;
	    }
		
	    if (card->ident_type & TUPLE_IDENT) {
		arg.tuple.DesiredTuple = card->id.tuple.code;
		arg.tuple.Attributes = 0;
		ret = ioctl(s->fd, DS_GET_FIRST_TUPLE, &arg);
		if (ret != 0) continue;
		arg.tuple.TupleOffset = card->id.tuple.ofs;
		ret = ioctl(s->fd, DS_GET_TUPLE_DATA, &arg);
		if (ret != 0) continue;
		if (strncmp((char *)arg.tuple_parse.data,
			    card->id.tuple.info,
			    strlen(card->id.tuple.info)) != 0)
		    continue;
	    }

	    break; /* we have a match */
	}
    }

    /* Check PCI vendor/device info */
    if (get_pci_id(ns, &pci_id)) {
	pci_id_t *p;
	if (!card) {
	    for (card = root_card; card; card = card->next)
		if ((card->ident_type == PCI_IDENT) &&
		    (pci_id.vendor == card->manfid.manf) &&
		    (pci_id.device == card->manfid.card))
		    break;
	}
	for (p = hotplug_list; p; p = p->next)
	    if ((pci_id.vendor == p->vendor) &&
		(pci_id.device == p->device)) break;
	if (p)
	    s->state |= SOCKET_HOTPLUG;
    }
    
    /* Try for a FUNCID match */
    if (!card && (funcid.func != 0xff)) {
	for (card = root_func; card; card = card->next)
	    if (card->id.func.funcid == funcid.func)
		break;
    }

    if (card) {
	syslog(LOG_INFO, "socket %d: %s", ns, card->name);
	beep(BEEP_TIME, BEEP_OK);
	if (verbose) log_card_info(vers, &manfid, &funcid, &pci_id);
	return card;
    }

    status.Function = 0;
    if (!blank_card || (status.CardState & CS_EVENT_CB_DETECT) ||
	manfid.manf || manfid.card || pci_id.vendor || vers) {
	syslog(LOG_INFO, "unsupported card in socket %d", ns);
	if (one_pass) return NULL;
	beep(BEEP_TIME, BEEP_ERR);
	log_card_info(vers, &manfid, &funcid, &pci_id);
	return NULL;
    } else {
	card = blank_card;
	syslog(LOG_INFO, "socket %d: %s", ns, card->name);
	beep(BEEP_TIME, BEEP_WARN);
	return card;
    }
}

/*====================================================================*/

static void load_config(void)
{
    if (chdir(configpath) != 0) {
	syslog(LOG_ERR, "chdir to %s failed: %m", configpath);
	exit(EXIT_FAILURE);
    }
    if (parse_configfile("config") != 0)
	exit(EXIT_FAILURE);
    if (root_device == NULL)
	syslog(LOG_WARNING, "no device drivers defined");
    if ((root_card == NULL) && (root_func == NULL))
	syslog(LOG_WARNING, "no cards defined");
}

/*====================================================================*/

static void free_card(card_info_t *card)
{
    if (card && (--card->refs == 0)) {
	int i;
	free(card->name);
	switch(card->ident_type) {
	case VERS_1_IDENT:
	    for (i = 0; i < card->id.vers.ns; i++)
		free(card->id.vers.pi[i]);
	break;
	case TUPLE_IDENT:
	    free(card->id.tuple.info);
	    break;
	default:
	    break;
	}
	free(card);
    }
}

static void free_device(device_info_t *dev)
{
    if (dev && (--dev->refs == 0)) {
	int i;
	for (i = 0; i < dev->modules; i++) {
	    free(dev->module[i]);
	    if (dev->opts[i]) free(dev->opts[i]);
	}
	if (dev->class) free(dev->class);
	free(dev);
    }
}

static void free_mtd(mtd_ident_t *mtd)
{
    if (mtd && (--mtd->refs == 0)) {
	free(mtd->name);
	free(mtd->module);
	free(mtd);
    }
}

static void free_config(void)
{
    while (root_adjust != NULL) {
	adjust_list_t *adj = root_adjust;
	root_adjust = root_adjust->next;
	free(adj);
    }
    
    while (root_device != NULL) {
	device_info_t *dev = root_device;
	root_device = root_device->next;
	free_device(dev);
    }

    while (root_card != NULL) {
	card_info_t *card = root_card;
	root_card = root_card->next;
	free_card(card);
    }
    
    while (root_func != NULL) {
	card_info_t *card = root_func;
	root_func = root_func->next;
	free_card(card);
    }
    blank_card = NULL;
    
    while (root_mtd != NULL) {
	mtd_ident_t *mtd = root_mtd;
	root_mtd = root_mtd->next;
	free_mtd(mtd);
    }
    default_mtd = NULL;
}

/*====================================================================*/

static int execute(char *msg, char *cmd)
{
    int ret;
    FILE *f;
    char line[256];

    syslog(LOG_INFO, "executing: '%s'", cmd);
    strcat(cmd, " 2>&1");
    f = popen(cmd, "r");
    while (fgets(line, 255, f)) {
	line[strlen(line)-1] = '\0';
	syslog(LOG_INFO, "+ %s", line);
    }
    ret = pclose(f);
    if (WIFEXITED(ret)) {
	if (WEXITSTATUS(ret))
	    syslog(LOG_INFO, "%s exited with status %d",
		   msg, WEXITSTATUS(ret));
	return WEXITSTATUS(ret);
    } else
	syslog(LOG_INFO, "%s exited on signal %d",
	       msg, WTERMSIG(ret));
    return -1;
}

/*====================================================================*/

static int execute_on_dev(char *action, char *class, char *dev)
{
    /* Fixed length strings are ok here */
    char msg[128], cmd[128];

    sprintf(msg, "%s cmd", action);
    sprintf(cmd, "./%s %s %s", class, action, dev);
    return execute(msg, cmd);
}

static int execute_on_all(char *cmd, char *class, int sn, int fn)
{
    socket_info_t *s = &socket[sn];
    bind_info_t *bind;
    int ret = 0;
    for (bind = s->bind[fn]; bind != NULL; bind = bind->next)
	if (bind->name[0] && (bind->name[2] != '#'))
	    ret |= execute_on_dev(cmd, class, bind->name);
    return ret;
}

/*====================================================================*/

#ifdef __linux__

typedef struct module_list_t {
    char *mod;
    int usage;
    struct module_list_t *next;
} module_list_t;

static module_list_t *module_list = NULL;

static int try_insmod(char *mod, char *opts)
{
    char *cmd = malloc(strlen(mod) + strlen(modpath) +
		       (opts ? strlen(opts) : 0) + 30);
    int ret;

    strcpy(cmd, "insmod ");
    if (strchr(mod, '/') != NULL)
	sprintf(cmd+7, "%s/%s.o", modpath, mod);
    else
	sprintf(cmd+7, "%s/pcmcia/%s.o", modpath, mod);
    if (access(cmd+7, R_OK) != 0) {
	syslog(LOG_INFO, "module %s not available", cmd+7);
	free(cmd);
	return -1;
    }
    if (opts) {
	strcat(cmd, " ");
	strcat(cmd, opts);
    }
    ret = execute("insmod", cmd);
    free(cmd);
    return ret;
}

static int try_modprobe(char *mod, char *opts)
{
    char *cmd = malloc(strlen(mod) + (opts ? strlen(opts) : 0) + 20);
    char *s = strrchr(mod, '/');
    int ret;

    sprintf(cmd, "modprobe %s", (s) ? s+1 : mod);
    if (opts) {
	strcat(cmd, " ");
	strcat(cmd, opts);
    }
    ret = execute("modprobe", cmd);
    free(cmd);
    return ret;
}

static void install_module(char *mod, char *opts)
{
    module_list_t *ml;

    for (ml = module_list; ml != NULL; ml = ml->next)
	if (strcmp(mod, ml->mod) == 0) break;
    if (ml == NULL) {
	ml = (module_list_t *)malloc(sizeof(struct module_list_t));
	ml->mod = mod;
	ml->usage = 0;
	ml->next = module_list;
	module_list = ml;
    }
    ml->usage++;
    if (ml->usage != 1)
	return;

#ifdef __linux__
    if (access("/proc/bus/pccard/drivers", R_OK) == 0) {
	FILE *f = fopen("/proc/bus/pccard/drivers", "r");
	if (f) {
	    char a[61], s[33];
	    while (fgets(a, 60, f)) {
		int is_kernel;
		sscanf(a, "%s %d", s, &is_kernel);
		if (strcmp(s, mod) != 0) continue;
		/* If it isn't a module, we won't try to rmmod */
		ml->usage += is_kernel;
		fclose(f);
		return;
	    }
	    fclose(f);
	}
    }
#endif

    if (do_modprobe) {
	if (try_modprobe(mod, opts) != 0)
	    try_insmod(mod, opts);
    } else {
	if (try_insmod(mod, opts) != 0)
	    try_modprobe(mod, opts);
    }
}

static void remove_module(char *mod)
{
    char *s, cmd[128];
    module_list_t *ml;

    for (ml = module_list; ml != NULL; ml = ml->next)
	if (strcmp(mod, ml->mod) == 0) break;
    if (ml != NULL) {
	ml->usage--;
	if (ml->usage == 0) {
	    /* Strip off leading path names */
	    s = strrchr(mod, '/');
	    s = (s) ? s+1 : mod;
	    sprintf(cmd, do_modprobe ? "modprobe -r %s" : "rmmod %s", s);
	    execute(do_modprobe ? "modprobe" : "rmmod", cmd);
	}
    }
}

#endif /* __linux__ */

/*====================================================================*/

#ifdef __BEOS__

#define install_module(a,b)
#define remove_module(a)

static void republish_driver(char *mod)
{
    int fd = open("/dev", O_RDWR);
    write(fd, mod, strlen(mod));
    close(fd);
}

#endif /* __BEOS__ */

/*====================================================================*/

static mtd_ident_t *lookup_mtd(region_info_t *region)
{
    mtd_ident_t *mtd;
    int match = 0;
    
    for (mtd = root_mtd; mtd; mtd = mtd->next) {
	switch (mtd->mtd_type) {
	case JEDEC_MTD:
	    if ((mtd->jedec_mfr == region->JedecMfr) &&
		(mtd->jedec_info == region->JedecInfo)) {
		match = 1;
		break;
	    }
	case DTYPE_MTD:
	    break;
	default:
	    break;
	}
	if (match) break;
    }
    if (mtd)
	return mtd;
    else
	return default_mtd;
}

/*====================================================================*/

static void bind_mtd(int sn)
{
    socket_info_t *s = &socket[sn];
    region_info_t region;
    bind_info_t bind;
    mtd_info_t mtd_info;
    mtd_ident_t *mtd;
    int i, attr, ret, nr;

    nr = 0;
    for (attr = 0; attr < 2; attr++) {
	region.Attributes = attr;
	ret = ioctl(s->fd, DS_GET_FIRST_REGION, &region);
	while (ret == 0) {
	    mtd = lookup_mtd(&region);
	    if (mtd) {
		/* Have we seen this MTD before? */
		for (i = 0; i < nr; i++)
		    if (s->mtd[i] == mtd) break;
		if (i == nr) {
		    install_module(mtd->module, mtd->opts);
		    s->mtd[nr] = mtd;
		    mtd->refs++;
		    nr++;
		}
		syslog(LOG_INFO, "  %s memory region at 0x%x: %s",
		       attr ? "Attribute" : "Common", region.CardOffset,
		       mtd->name);
		/* Bind MTD to this region */
		strcpy(mtd_info.dev_info, s->mtd[i]->module);
		mtd_info.Attributes = region.Attributes;
		mtd_info.CardOffset = region.CardOffset;
		if (ioctl(s->fd, DS_BIND_MTD, &mtd_info) != 0) {
		    syslog(LOG_INFO,
			   "bind MTD '%s' to region at 0x%x failed: %m",
			   (char *)mtd_info.dev_info, region.CardOffset);
		}
	    }
	    ret = ioctl(s->fd, DS_GET_NEXT_REGION, &region);
	}
    }
    s->mtd[nr] = NULL;
    
    /* Now bind each unique MTD as a normal client of this socket */
    for (i = 0; i < nr; i++) {
	strcpy(bind.dev_info, s->mtd[i]->module);
	bind.function = 0;
	if (ioctl(s->fd, DS_BIND_REQUEST, &bind) != 0)
	    syslog(LOG_INFO, "bind MTD '%s' to socket %d failed: %m",
		   (char *)bind.dev_info, sn);
    }
}

/*====================================================================*/

static void update_cis(socket_info_t *s)
{
    cisdump_t cis;
    FILE *f = fopen(s->card->cis_file, "r");
    if (f == NULL)
	syslog(LOG_ERR, "could not open '%s': %m", s->card->cis_file);
    else {
	cis.Length = fread(cis.Data, 1, CISTPL_MAX_CIS_SIZE, f);
	fclose(f);
	if (ioctl(s->fd, DS_REPLACE_CIS, &cis) != 0)
	    syslog(LOG_ERR, "could not replace CIS: %m");
    }
}

/*====================================================================*/

static void do_insert(int sn)
{
    socket_info_t *s = &socket[sn];
    card_info_t *card;
    device_info_t **dev;
    bind_info_t *bind, **tail;
    int i, j, ret;

    /* Already identified? */
    if ((s->card != NULL) && (s->card != blank_card))
	return;
    
    syslog(LOG_INFO, "initializing socket %d", sn);
    card = lookup_card(sn);
    /* Make sure we've learned something new before continuing */
    if (card == s->card)
	return;
    s->card = card;
    card->refs++;
    if (s->state & SOCKET_HOTPLUG) {
	write_stab();
	return;
    }
    if (card->cis_file) update_cis(s);

    dev = card->device;

    /* Set up MTD's */
    for (i = 0; i < card->bindings; i++)
	if (dev[i]->needs_mtd)
	    break;
    if (i < card->bindings)
	bind_mtd(sn);

#ifdef __linux__
    /* Install kernel modules */
    for (i = 0; i < card->bindings; i++) {
	dev[i]->refs++;
	for (j = 0; j < dev[i]->modules; j++)
	    install_module(dev[i]->module[j], dev[i]->opts[j]);
    }
#endif
    
    /* Bind drivers by their dev_info identifiers */
    for (i = 0; i < card->bindings; i++) {
	bind = calloc(1, sizeof(bind_info_t));
	strcpy((char *)bind->dev_info, (char *)dev[i]->dev_info);
	if (strcmp(bind->dev_info, "cb_enabler") == 0)
	    bind->function = BIND_FN_ALL;
	else
	    bind->function = card->dev_fn[i];
	if (ioctl(s->fd, DS_BIND_REQUEST, bind) != 0) {
	    if (errno == EBUSY) {
		syslog(LOG_INFO, "'%s' already bound to socket %d",
		       (char *)bind->dev_info, sn);
	    } else {
		syslog(LOG_INFO, "bind '%s' to socket %d failed: %m",
		       (char *)bind->dev_info, sn);
		beep(BEEP_TIME, BEEP_ERR);
		write_stab();
		return;
	    }
	}

#ifdef __BEOS__
	republish_driver(dev[i]->module[0]);
#endif

	for (ret = j = 0; j < 10; j++) {
	    ret = ioctl(s->fd, DS_GET_DEVICE_INFO, bind);
	    if ((ret == 0) || (errno != EAGAIN))
		break;
	    usleep(100000);
	}
	if (ret != 0) {
	    syslog(LOG_INFO, "get dev info on socket %d failed: %m",
		   sn);
	    ioctl(s->fd, DS_UNBIND_REQUEST, bind);
	    beep(BEEP_TIME, BEEP_ERR);
	    write_stab();
	    return;
	}
	tail = &s->bind[i];
	while (ret == 0) {
	    bind_info_t *old;
#ifdef __linux__
	    if ((strlen(bind->name) > 3) && (bind->name[2] == '#'))
		xlate_scsi_name(bind);
#endif
	    old = *tail = bind; tail = (bind_info_t **)&bind->next;
	    bind = (bind_info_t *)malloc(sizeof(bind_info_t));
	    memcpy(bind, old, sizeof(bind_info_t));
	    ret = ioctl(s->fd, DS_GET_NEXT_DEVICE, bind);
	}
	*tail = NULL; free(bind);
	write_stab();
    }

    /* Run "start" commands */
    for (i = ret = 0; i < card->bindings; i++)
	if (dev[i]->class)
	    ret |= execute_on_all("start", dev[i]->class, sn, i);
    if (ret)
	beep(BEEP_TIME, BEEP_ERR);
    else
	beep(BEEP_TIME, BEEP_OK);
    
}

/*====================================================================*/

static int do_check(int sn)
{
    socket_info_t *s = &socket[sn];
    card_info_t *card;
    device_info_t **dev;
    int i, ret;

    card = s->card;
    if (card == NULL)
	return 0;
    
    /* Run "check" commands */
    dev = card->device;
    for (i = 0; i < card->bindings; i++) {
	if (dev[i]->class) {
	    ret = execute_on_all("check", dev[i]->class, sn, i);
	    if (ret != 0)
		return CS_IN_USE;
	}
    }
    return 0;
}

/*====================================================================*/

static void do_remove(int sn)
{
    socket_info_t *s = &socket[sn];
    card_info_t *card;
    device_info_t **dev;
    bind_info_t *bind;
    int i, j;

    card = s->card;
    if (card == NULL)
	goto done;
    
    syslog(LOG_INFO, "shutting down socket %d", sn);
    if (s->state & SOCKET_HOTPLUG)
	goto done;
    
    /* Run "stop" commands */
    dev = card->device;
    for (i = 0; i < card->bindings; i++) {
	if (dev[i]->class) {
	    execute_on_all("stop", dev[i]->class, sn, i);
	}
    }

    /* unbind driver instances */
    for (i = 0; i < card->bindings; i++) {
	if (s->bind[i]) {
	    if (ioctl(s->fd, DS_UNBIND_REQUEST, s->bind[i]) != 0)
		syslog(LOG_INFO, "unbind '%s' from socket %d failed: %m",
		       (char *)s->bind[i]->dev_info, sn);
	    while (s->bind[i]) {
		bind = s->bind[i];
		s->bind[i] = bind->next;
		free(bind);
	    }
	}
    }
    for (i = 0; (s->mtd[i] != NULL); i++) {
	bind_info_t b;
	strcpy(b.dev_info, s->mtd[i]->module);
	b.function = 0;
	if (ioctl(s->fd, DS_UNBIND_REQUEST, &b) != 0)
	    syslog(LOG_INFO, "unbind MTD '%s' from socket %d failed: %m",
		   s->mtd[i]->module, sn);
    }

    /* remove kernel modules in inverse order */
    for (i = 0; i < card->bindings; i++) {
	for (j = dev[i]->modules-1; j >= 0; j--)
	    remove_module(dev[i]->module[j]);
	free_device(dev[i]);
    }
    /* Remove any MTD's bound to this socket */
    for (i = 0; (s->mtd[i] != NULL); i++) {
	remove_module(s->mtd[i]->module);
	free_mtd(s->mtd[i]);
	s->mtd[i] = NULL;
    }

done:
    beep(BEEP_TIME, BEEP_OK);
    free_card(card);
    s->card = NULL;
    write_stab();
}

/*====================================================================*/

static void do_suspend(int sn)
{
    socket_info_t *s = &socket[sn];
    card_info_t *card;
    device_info_t **dev;
    int i, ret;
    
    card = s->card;
    if (card == NULL)
	return;
    dev = card->device;
    for (i = 0; i < card->bindings; i++) {
	if (dev[i]->class) {
	    ret = execute_on_all("suspend", dev[i]->class, sn, i);
	    if (ret != 0)
		beep(BEEP_TIME, BEEP_ERR);
	}
    }
}

/*====================================================================*/

static void do_resume(int sn)
{
    socket_info_t *s = &socket[sn];
    card_info_t *card;
    device_info_t **dev;
    int i, ret;
    
    card = s->card;
    if (card == NULL)
	return;
    dev = card->device;
    for (i = 0; i < card->bindings; i++) {
	if (dev[i]->class) {
	    ret = execute_on_all("resume", dev[i]->class, sn, i);
	    if (ret != 0)
		beep(BEEP_TIME, BEEP_ERR);
	}
    }
}

/*====================================================================*/

static void wait_for_pending(void)
{
    cs_status_t status;
    int i;
    status.Function = 0;
    for (;;) {
	usleep(100000);
	for (i = 0; i < sockets; i++)
	    if ((ioctl(socket[i].fd, DS_GET_STATUS, &status) == 0) &&
		(status.CardState & CS_EVENT_CARD_INSERTION))
		break;
	if (i == sockets) break;
    }
}

/*====================================================================*/

static void free_resources(void)
{
    adjust_list_t *al;
    int fd = socket[0].fd;

    for (al = root_adjust; al; al = al->next) {
	if (al->adj.Action == ADD_MANAGED_RESOURCE) {
	    al->adj.Action = REMOVE_MANAGED_RESOURCE;
	    ioctl(fd, DS_ADJUST_RESOURCE_INFO, &al->adj);
	} else if ((al->adj.Action == REMOVE_MANAGED_RESOURCE) &&
		   (al->adj.Resource == RES_IRQ)) {
	    al->adj.Action = ADD_MANAGED_RESOURCE;
	    ioctl(fd, DS_ADJUST_RESOURCE_INFO, &al->adj);
	}
    }
    
}

/*====================================================================*/

static void adjust_resources(void)
{
    adjust_list_t *al;
    int ret;
    char tmp[64];
    int fd = socket[0].fd;
    
    for (al = root_adjust; al; al = al->next) {
	ret = ioctl(fd, DS_ADJUST_RESOURCE_INFO, &al->adj);
	if (ret != 0) {
	    switch (al->adj.Resource) {
	    case RES_MEMORY_RANGE:
		sprintf(tmp, "memory %#lx-%#lx",
			al->adj.resource.memory.Base,
			al->adj.resource.memory.Base +
			al->adj.resource.memory.Size - 1);
		break;
	    case RES_IO_RANGE:
		sprintf(tmp, "IO ports %#x-%#x",
			al->adj.resource.io.BasePort,
			al->adj.resource.io.BasePort +
			al->adj.resource.io.NumPorts - 1);
		break;
	    case RES_IRQ:
		sprintf(tmp, "irq %u", al->adj.resource.irq.IRQ);
		break;
	    }
	    syslog(LOG_INFO, "could not adjust resource: %s: %m", tmp);
	}
    }
}
    
/*====================================================================*/

static int cleanup_files = 0;

static void fork_now(void)
{
    int ret;
    if ((ret = fork()) > 0) {
	cleanup_files = 0;
	exit(0);
    }
    if (ret == -1)
	syslog(LOG_ERR, "forking: %m");
    if (setsid() < 0)
	syslog(LOG_ERR, "detaching from tty: %m");
}    

static void done(void)
{
    syslog(LOG_INFO, "exiting");
    if (cleanup_files) {
	unlink(pidfile);
	unlink(stabfile);
    }
}

/*====================================================================*/

/* most recent signal */
static int caught_signal = 0;

static void catch_signal(int sig)
{
    caught_signal = sig;
    if (signal(sig, catch_signal) == SIG_ERR)
	syslog(LOG_INFO, "signal(%d): %m", sig);
}

static void handle_signal(void)
{
    int i;
    switch (caught_signal) {
    case SIGTERM:
    case SIGINT:
	for (i = 0; i < sockets; i++)
	    if ((socket[i].state & SOCKET_PRESENT) &&
		(do_check(i) == 0)) do_remove(i);
	free_resources();
	exit(0);
	break;
    case SIGHUP:
	free_resources();
	free_config();
	syslog(LOG_INFO, "re-loading config file");
	load_config();
	adjust_resources();
	break;
#ifdef SIGPWR
    case SIGPWR:
	break;
#endif
    }
}

/*====================================================================*/

static int init_sockets(void)
{
    int fd, i;
    servinfo_t serv;

#ifdef __linux__
    major = lookup_dev("pcmcia");
    if (major < 0) {
	if (major == -ENODEV)
	    syslog(LOG_ERR, "no pcmcia driver in /proc/devices");
	else
	    syslog(LOG_ERR, "could not open /proc/devices: %m");
	exit(EXIT_FAILURE);
    }
#endif
    for (fd = -1, i = 0; i < MAX_SOCKS; i++) {
	fd = open_sock(i, S_IFCHR|S_IREAD|S_IWRITE);
	if (fd < 0) break;
	socket[i].fd = fd;
	socket[i].state = 0;
    }
    if ((fd < 0) && (errno != ENODEV) && (errno != ENOENT))
	syslog(LOG_ERR, "open_sock(socket %d) failed: %m", i);
    sockets = i;
    if (sockets == 0) {
	syslog(LOG_ERR, "no sockets found!");
	return -1;
    } else
	syslog(LOG_INFO, "watching %d sockets", sockets);

    if (ioctl(socket[0].fd, DS_GET_CARD_SERVICES_INFO, &serv) == 0) {
	if (serv.Revision != CS_RELEASE_CODE)
	    syslog(LOG_INFO, "Card Services release does not match");
    } else {
	syslog(LOG_ERR, "could not get CS revision info!");
	return -1;
    }
    adjust_resources();
    return 0;
}

/*====================================================================*/

int main(int argc, char *argv[])
{
    int optch, errflg;
    int i, max_fd, ret, event, pass;
    int delay_fork = 0;
    struct timeval tv;
    fd_set fds;

    if (access("/var/lib/pcmcia", R_OK) == 0) {
	stabfile = "/var/lib/pcmcia/stab";
    } else {
	stabfile = "/var/run/stab";
    }

    errflg = 0;
    while ((optch = getopt(argc, argv, "Vqdvofc:m:p:s:")) != -1) {
	switch (optch) {
	case 'V':
	    fprintf(stderr, "cardmgr version " CS_RELEASE "\n");
	    return 0;
	    break;
	case 'q':
	    be_quiet = 1; break;
	case 'v':
	    verbose = 1; break;
	case 'o':
	    one_pass = 1; break;
	case 'f':
	    delay_fork = 1; break;
	case 'c':
	    configpath = strdup(optarg); break;
#ifdef __linux__
	case 'd':
	    do_modprobe = 1; break;
	case 'm':
	    modpath = strdup(optarg); break;
#endif
	case 'p':
	    pidfile = strdup(optarg); break;
	case 's':
	    stabfile = strdup(optarg); break;
	default:
	    errflg = 1; break;
	}
    }
    if (errflg || (optind < argc)) {
	fprintf(stderr, "usage: %s [-V] [-q] [-v] [-d] [-o] [-f] "
		"[-c configpath] [-m modpath]\n               "
		"[-p pidfile] [-s stabfile]\n", argv[0]);
	exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    openlog("cardmgr", LOG_PID|LOG_PERROR, LOG_DAEMON);
#else
    openlog("cardmgr", LOG_PID|LOG_CONS, LOG_DAEMON);
    close(0); close(1); close(2);
    if (!delay_fork && !one_pass)
	fork_now();
#endif
    
    syslog(LOG_INFO, "starting, version is " CS_RELEASE);
    atexit(&done);
    putenv("PATH=/bin:/sbin:/usr/bin:/usr/sbin");
    if (verbose)
	putenv("VERBOSE=1");

#ifdef __linux__
    if (modpath == NULL) {
	if (access("/lib/modules/preferred", X_OK) == 0)
	    modpath = "/lib/modules/preferred";
	else {
	    struct utsname utsname;
	    if (uname(&utsname) != 0) {
		syslog(LOG_ERR, "uname(): %m");
		exit(EXIT_FAILURE);
	    }
	    modpath = (char *)malloc(strlen(utsname.release)+14);
	    sprintf(modpath, "/lib/modules/%s", utsname.release);
	}
    }
    if (access(modpath, X_OK) != 0)
	syslog(LOG_INFO, "cannot access %s: %m", modpath);
    /* We default to using modprobe if it is available */
    do_modprobe |= (access("/sbin/modprobe", X_OK) == 0);
    load_pcimap();
#endif /* __linux__ */
    
    load_config();
    
    if (init_sockets() != 0)
	exit(EXIT_FAILURE);

    /* If we've gotten this far, then clean up pid and stab at exit */
    write_pid();
    write_stab();
    cleanup_files = 1;
    
    if (signal(SIGHUP, catch_signal) == SIG_ERR)
	syslog(LOG_ERR, "signal(SIGHUP): %m");
    if (signal(SIGTERM, catch_signal) == SIG_ERR)
	syslog(LOG_ERR, "signal(SIGTERM): %m");
    if (signal(SIGINT, catch_signal) == SIG_ERR)
	syslog(LOG_ERR, "signal(SIGINT): %m");
#ifdef SIGPWR
    if (signal(SIGPWR, catch_signal) == SIG_ERR)
	syslog(LOG_ERR, "signal(SIGPWR): %m");
#endif
    
    for (i = max_fd = 0; i < sockets; i++)
	max_fd = (socket[i].fd > max_fd) ? socket[i].fd : max_fd;

    /* First select() call: poll, don't wait */
    tv.tv_sec = tv.tv_usec = 0;

    /* Wait for sockets in setup-pending state to settle */
    if (one_pass || delay_fork)
	wait_for_pending();
    
    for (pass = 0; ; pass++) {
	FD_ZERO(&fds);
	for (i = 0; i < sockets; i++)
	    FD_SET(socket[i].fd, &fds);

	while ((ret = select(max_fd+1, &fds, NULL, NULL,
			     ((pass == 0) ? &tv : NULL))) < 0) {
	    if (errno == EINTR) {
		handle_signal();
	    } else {
		syslog(LOG_ERR, "select(): %m");
		exit(EXIT_FAILURE);
	    }
	}

	for (i = 0; i < sockets; i++) {
	    if (!FD_ISSET(socket[i].fd, &fds))
		continue;
	    ret = read(socket[i].fd, &event, 4);
	    if ((ret == -1) && (errno != EAGAIN))
		syslog(LOG_INFO, "read(%d): %m\n", i);
	    if (ret != 4)
		continue;
	    
	    switch (event) {
	    case CS_EVENT_CARD_REMOVAL:
		socket[i].state = 0;
		do_remove(i);
		break;
	    case CS_EVENT_EJECTION_REQUEST:
		ret = do_check(i);
		if (ret == 0) {
		    socket[i].state = 0;
		    do_remove(i);
		}
		write(socket[i].fd, &ret, 4);
		break;
	    case CS_EVENT_CARD_INSERTION:
	    case CS_EVENT_INSERTION_REQUEST:
		socket[i].state |= SOCKET_PRESENT;
	    case CS_EVENT_CARD_RESET:
		socket[i].state |= SOCKET_READY;
		do_insert(i);
		break;
	    case CS_EVENT_RESET_PHYSICAL:
		socket[i].state &= ~SOCKET_READY;
		break;
	    case CS_EVENT_PM_SUSPEND:
		do_suspend(i);
		break;
	    case CS_EVENT_PM_RESUME:
		do_resume(i);
		break;
	    }
	    
	}

	if (one_pass)
	    exit(EXIT_SUCCESS);
	if (delay_fork) {
	    fork_now();
	    write_pid();
	}
	
    } /* repeat */
    return 0;
}
