/*======================================================================

    X Windows PCMCIA device control program

    cardinfo.c 1.35 2001/05/12 22:45:59

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

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <forms.h>

#undef Status
#include <pcmcia/config.h>
#include <pcmcia/version.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ds.h>

/*====================================================================*/

typedef enum s_state {
    S_EMPTY, S_PRESENT, S_READY, S_BUSY, S_SUSPEND
} s_state;

typedef struct field_t {
    char *str;
    FL_OBJECT *obj;
} field_t;

typedef struct flag_t {
    int val;
    FL_OBJECT *obj;
} flag_t;

typedef struct socket_info_t {
    int fd, o_state;
    FL_OBJECT *menu;
    field_t card, state, dev, io, irq;
    flag_t cd, vcc, vpp, wp;
} socket_info_t;

#define MAX_SOCK 8

static int ns;
static socket_info_t st[MAX_SOCK];

static FL_OBJECT *event_log;

static char *pidfile = "/var/run/cardmgr.pid";
static char *stabfile;

/*====================================================================*/

typedef struct event_tag_t {
    event_t event;
    char *name;
} event_tag_t;

static event_tag_t event_tag[] = {
    { CS_EVENT_CARD_INSERTION, "card insertion" },
    { CS_EVENT_CARD_REMOVAL, "card removal" },
    { CS_EVENT_RESET_PHYSICAL, "prepare for reset" },
    { CS_EVENT_CARD_RESET, "card reset successful" },
    { CS_EVENT_RESET_COMPLETE, "reset request complete" },
    { CS_EVENT_EJECTION_REQUEST, "user eject request" },
    { CS_EVENT_INSERTION_REQUEST, "user insert request" },
    { CS_EVENT_PM_SUSPEND, "suspend card" },
    { CS_EVENT_PM_RESUME, "resume card" },
    { CS_EVENT_REQUEST_ATTENTION, "request attention" },
};
#define NTAGS (sizeof(event_tag)/sizeof(event_tag_t))

/*====================================================================*/

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
} /* lookup_dev */

/*====================================================================*/

static int open_dev(dev_t dev)
{
    static char *paths[] = {
	"/var/lib/pcmcia", "/var/run", "/dev", "/tmp", NULL
    };
    char **p, fn[64];
    int fd;

    for (p = paths; *p; p++) {
	sprintf(fn, "%s/ci-%d", *p, getpid());
	if (mknod(fn, (S_IFCHR|S_IREAD), dev) == 0)
	    break;
    }
    if (!*p)
	return -1;
    if ((fd = open(fn, O_RDONLY)) < 0) {
	unlink(fn);
	return -1;
    }
    if (unlink(fn) != 0) {
	close(fd);
	return -1;
    }
    return fd;
} /* open_dev */

/*====================================================================*/

static void do_alert(char *fmt, ...)
{
    char msg[132];
    va_list args;
    va_start(args, fmt);
    vsprintf(msg, fmt, args);
    fl_show_alert(msg, "", "", 0);
    va_end(args);
} /* do_alert */

/*====================================================================*/

static void do_menu(FL_OBJECT *obj, long i)
{
    int ret = 0;

    switch (fl_get_menu(obj)) {
    case 1:
	/* do_opts(); */ break;
    case 2:
	ret = ioctl(st[i].fd, DS_RESET_CARD); break;
    case 3:
	ret = ioctl(st[i].fd, DS_SUSPEND_CARD); break;
    case 4:
	ret = ioctl(st[i].fd, DS_RESUME_CARD); break;
    case 5:
	ret = ioctl(st[i].fd, DS_EJECT_CARD); break;
    case 6:
	ret = ioctl(st[i].fd, DS_INSERT_CARD); break;
    }
    if (ret != 0)
	do_alert("ioctl() operation failed: %s", strerror(errno));
} /* do_menu */

/*====================================================================*/

static void do_quit(FL_OBJECT *obj, long data)
{
    exit(0);
}

/*====================================================================*/

static void do_reset(FL_OBJECT *obj, long data)
{
    FILE *f;
    pid_t pid;
    
    f = fopen(pidfile, "r");
    if (f == NULL) {
	do_alert("Could not open pidfile: %s", strerror(errno));
	return;
    }
    if (fscanf(f, "%d", &pid) != 1) {
	do_alert("Could not read pidfile");
	return;
    }
    if (kill(pid, SIGHUP) != 0)
	do_alert("Could not signal cardmgr: %s", strerror(errno));
}

/*====================================================================*/

void new_field(field_t *field, int x, int y, int w1, int w2, char *label)
{
    FL_OBJECT *obj;
    if (w1 > 0) {
	obj = fl_add_text(FL_NORMAL_TEXT, x, y, w1, 20, label);
	fl_set_object_boxtype(obj, FL_NO_BOX);
    }
    field->str = strdup("");
    field->obj = fl_add_box(FL_BORDER_BOX, x+w1, y, w2, 20, "");
    fl_set_object_color(field->obj, FL_MCOL, 0);
}

void update_field(field_t *field, char *new)
{
    if (strcmp(field->str, new) != 0) {
	free(field->str);
	field->str = strdup(new);
	fl_set_object_label(field->obj, new);
    }
}

void new_flag(flag_t *flag, int x, int y, char *label)
{
    flag->obj = fl_add_box(FL_ROUNDED_BOX, x, y, 30, 20, label);
    fl_set_object_color(flag->obj, FL_MCOL, 0);
    fl_hide_object(flag->obj);
    flag->val = 0;
}

void update_flag(flag_t *flag, int new)
{
    if (flag->val != new) {
	flag->val = new;
	if (new)
	    fl_show_object(flag->obj);
	else
	    fl_hide_object(flag->obj);
    }
}

/*====================================================================*/

static void do_update(FL_OBJECT *obj, long data)
{
    FILE *f;
    int i, j, event, ret, state;
    cs_status_t status;
    config_info_t cfg;
    char s[80], *t, d[80], io[20], irq[4];
    ioaddr_t stop;
    struct stat buf;
    static time_t last = 0;
    time_t now;
    struct tm *tm;
    fd_set fds;
    struct timeval timeout;

    fl_set_timer(obj, 0.3);

    /* Poll for events */
    FD_ZERO(&fds);
    for (i = 0; i < ns; i++)
	FD_SET(st[i].fd, &fds);
    timeout.tv_sec = timeout.tv_usec = 0;
    ret = select(MAX_SOCK+4, &fds, NULL, NULL, &timeout);
    now = time(NULL);
    tm = localtime(&now);
    if (ret > 0) {
	for (i = 0; i < ns; i++) {
	    if (!FD_ISSET(st[i].fd, &fds))
		continue;
	    ret = read(st[i].fd, &event, 4);
	    if (ret != 4) continue;
	    for (j = 0; j < NTAGS; j++)
		if (event_tag[j].event == event) break;
	    if (j == NTAGS)
		sprintf(s, "%2d:%02d:%02d  socket %d: unknown event 0x%x",
			tm->tm_hour, tm->tm_min, tm->tm_sec, i, event);
	    else
		sprintf(s, "%2d:%02d:%02d  socket %d: %s", tm->tm_hour,
			tm->tm_min, tm->tm_sec, i, event_tag[j].name);
	    fl_addto_browser(event_log, s);
	}
    }

    if ((stat(stabfile, &buf) == 0) && (buf.st_mtime >= last)) {
	f = fopen(stabfile, "r");
	if (f == NULL)
	    return;
	
	if (flock(fileno(f), LOCK_SH) != 0) {
	    do_alert("flock(stabfile) failed: %s", strerror(errno));
	    return;
	}
	last = now;
	fgetc(f);
	for (i = 0; i < ns; i++) {
	    if (!fgets(s, 80, f)) break;
	    s[strlen(s)-1] = '\0';
	    update_field(&st[i].card, s+9);
	    *d = '\0';
	    for (;;) {
		int c = fgetc(f);
		if ((c == EOF) || (c == 'S')) {
		    update_field(&st[i].dev, d);
		    break;
		} else {
		    fgets(s, 80, f);
		    for (t = s, j = 0; j < 4; j++)
			t = strchr(t, '\t')+1;
		    t[strcspn(t, "\t\n")] = '\0';
		    if (*d == '\0')
			strcpy(d, t);
		    else {
			strcat(d, ", ");
			strcat(d, t);
		    }
		}
	    }
	}
	flock(fileno(f), LOCK_UN);
	fclose(f);
    }

    for (i = 0; i < ns; i++) {
	
	state = S_EMPTY;
	status.Function = 0;
	ioctl(st[i].fd, DS_GET_STATUS, &status);
	if (strcmp(st[i].card.str, "empty") == 0) {
	    if (status.CardState & CS_EVENT_CARD_DETECT)
		state = S_PRESENT;
	} else {
	    if (status.CardState & CS_EVENT_PM_SUSPEND)
		state = S_SUSPEND;
	    else {
		if (status.CardState & CS_EVENT_READY_CHANGE)
		    state = S_READY;
		else
		    state = S_BUSY;
	    }
	}
	
	if (state != st[i].o_state) {
	    st[i].o_state = state;
	    for (j = 1; j <= 6; j++)
		fl_set_menu_item_mode(st[i].menu, j, FL_PUP_GRAY);
	    switch (state) {
	    case S_EMPTY:
		update_field(&st[i].state, "");
		break;
	    case S_PRESENT:
		fl_set_menu_item_mode(st[i].menu, 6, FL_PUP_NONE);
		update_field(&st[i].state, "");
		break;
	    case S_READY:
		fl_set_menu_item_mode(st[i].menu, 1, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 2, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 3, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 5, FL_PUP_NONE);
		update_field(&st[i].state, "ready");
		break;
	    case S_BUSY:
		fl_set_menu_item_mode(st[i].menu, 1, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 2, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 3, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 5, FL_PUP_NONE);
		update_field(&st[i].state, "not ready");
		break;
	    case S_SUSPEND:
		fl_set_menu_item_mode(st[i].menu, 1, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 4, FL_PUP_NONE);
		fl_set_menu_item_mode(st[i].menu, 5, FL_PUP_NONE);
		update_field(&st[i].state, "suspended");
		break;
	    }
	}

	strcpy(io, "");
	strcpy(irq, "");
	memset(&cfg, 0, sizeof(cfg));
	ret = ioctl(st[i].fd, DS_GET_CONFIGURATION_INFO, &cfg);
	if (cfg.Attributes & CONF_VALID_CLIENT) {
	    if (cfg.AssignedIRQ != 0)
		sprintf(irq, "%d", cfg.AssignedIRQ);
	    if (cfg.NumPorts1 > 0) {
		stop = cfg.BasePort1+cfg.NumPorts1;
		if (cfg.NumPorts2 > 0) {
		    if (stop == cfg.BasePort2)
			sprintf(io, "%#x-%#x", cfg.BasePort1,
				stop+cfg.NumPorts2-1);
		    else
			sprintf(io, "%#x-%#x, %#x-%#x", cfg.BasePort1, stop-1,
				cfg.BasePort2, cfg.BasePort2+cfg.NumPorts2-1);
		} else
		    sprintf(io, "%#x-%#x", cfg.BasePort1, stop-1);
	    }
	}
	update_field(&st[i].irq, irq);
	update_field(&st[i].io, io);

	update_flag(&st[i].cd, status.CardState & CS_EVENT_CARD_DETECT);
	update_flag(&st[i].vcc, cfg.Vcc > 0);
	update_flag(&st[i].vpp, cfg.Vpp1 > 0);
	update_flag(&st[i].wp, status.CardState & CS_EVENT_WRITE_PROTECT);
    }
}

/*====================================================================*/

int main(int argc, char *argv[])
{
    int i, ret, y, major;
    servinfo_t serv;
    char name[12];
    FL_FORM *form;
    FL_OBJECT *obj;

    if (geteuid() != 0) {
	fprintf(stderr, "cardinfo must be setuid root\n");
	exit(EXIT_FAILURE);
    }

    if (access("/var/lib/pcmcia", R_OK) == 0) {
	stabfile = "/var/lib/pcmcia/stab";
    } else {
	stabfile = "/var/run/stab";
    }
    
    major = lookup_dev("pcmcia");
    if (major < 0) {
	if (major == -ENODEV)
	    fprintf(stderr, "no pcmcia driver in /proc/devices\n");
	else
	    perror("could not open /proc/devices");
	exit(EXIT_FAILURE);
    }
    
    for (ns = 0; ns < MAX_SOCK; ns++) {
	st[ns].fd = open_dev((major<<8)+ns);
	if (st[ns].fd < 0) break;
    }
    if (ns == 0) {
	fprintf(stderr, "no sockets found\n");
	exit(EXIT_FAILURE);
    }

    if (ioctl(st[0].fd, DS_GET_CARD_SERVICES_INFO, &serv) == 0) {
	if (serv.Revision != CS_RELEASE_CODE)
	    fprintf(stderr, "Card Services release does not match!\n");
    } else {
	fprintf(stderr, "could not get CS revision info!\n");
	exit(EXIT_FAILURE);
    }
    
    /* Switch back to real user privileges, to be safe */
#ifndef UNSAFE_TOOLS
    setuid(getuid());
#endif

    if ((ret = fork()) > 0) exit(0);
    if (ret == -1)
	perror("forking");
    if (setsid() < 0)
	perror("detaching from tty");

#if (FL_REVISION >= 80)
    fl_flip_yorigin();
    fl_initialize(&argc, argv, "cardinfo", 0, 0);
#else
    fl_initialize(argv[0], "cardinfo", 0, 0, &argc, argv);
#endif
    
    form = fl_bgn_form(FL_BORDER_BOX, 400, ns*100+70);
    
    for (i = 0; i < ns; i++) {
	y = 100*(ns-i)+45;
	sprintf(name, "Socket %d", i);
	st[i].menu = obj =
	    fl_add_menu(FL_PULLDOWN_MENU, 10, y, 90, 20, name);
	fl_set_object_boxtype(obj, FL_UP_BOX);
	fl_set_object_callback(obj, do_menu, i);
	fl_show_menu_symbol(obj, 1);
	fl_set_menu(obj, "opts...|reset|suspend|resume|eject|insert");
	new_field(&st[i].card, 110, y, 0, 280, "");

	y -= 25;
	new_field(&st[i].state, 110, y, 40, 80, "state:");
	new_flag(&st[i].cd, 240, y, "CD");
	new_flag(&st[i].vcc, 280, y, "Vcc");
	new_flag(&st[i].vpp, 320, y, "Vpp");
	new_flag(&st[i].wp, 360, y, "WP");
	
	y -= 25;
	new_field(&st[i].dev, 110, y, 60, 160, "device(s):");

	y -= 25;
	new_field(&st[i].io, 110, y, 50, 150, "IO ports:");
	new_field(&st[i].irq, 310, y, 60, 20, "interrupt:");
	
    }

    event_log = fl_add_browser(FL_NORMAL_BROWSER, 10, 5, 270, 60, "");
#if (FL_REVISION < 88)
    fl_set_browser_leftslider(event_log, 1);
#endif
    fl_set_browser_fontsize(event_log, FL_SMALL_SIZE);
    
    obj = fl_add_button(FL_NORMAL_BUTTON, 300, 35, 90, 25, "reset");
    fl_set_object_callback(obj, do_reset, 0);
    obj = fl_add_button(FL_NORMAL_BUTTON, 300, 5, 90, 25, "quit");
    fl_set_object_callback(obj, do_quit, 0);

    obj = fl_add_timer(FL_HIDDEN_TIMER, 0, 0, 1, 2, "");
    fl_set_object_callback(obj, do_update, 0);
    
    fl_end_form();

    fl_show_form(form, FL_PLACE_SIZE, FL_FULLBORDER, "cardinfo");

    fl_set_timer(obj, 0.2);

    do {
	
	obj = fl_do_forms();

    } while (1);
    
    fl_hide_form(form);
    exit(EXIT_SUCCESS);
    return 0;
}
