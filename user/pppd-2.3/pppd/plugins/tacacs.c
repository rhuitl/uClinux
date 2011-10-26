/* tacacs.c v.0.3 Plugin for pppd. Implement TACACS+ protocol.
 * Copyright (C)-2000 Jean-Louis Noel (jln@stben.be)
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <pppd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <tacplus.h>
#include <libtac.h>
#include <fsm.h>
#include <ipcp.h>
#include <magic.h>
#include <time.h>

extern char *ttyname(int);

static bool   plugin_loaded = 0;
static bool   use_tacacs  = 0;
static bool   use_authorize  = 0;
static bool   use_account = 0;
static bool   authorized = 0;
static bool   logged_in = 0;
static int    task_id;
static u_long tac_server = -1;
static char   tac_secret_buffer[MAXSECRETLEN] = "";
static char   tty[32];

static int (*prev_pap_check_hook) __P((void));
static int (*prev_pap_auth_hook) __P((char *user, char *passwd, char **msgp,
				 struct wordlist **paddrs,
				 struct wordlist **popts));
static void (*prev_ip_up_hook) __P((void));
static void (*prev_ip_down_hook) __P((void));


static int
tacacs_get_server(char **argv);


static option_t tacacs_options[] =
{
    { "tacacs", o_bool, &use_tacacs,
      STR("Use TACACS+ functions"), 1 },
    { "tacacs-accounting", o_bool, &use_account,
      STR("Send TACACS+ accounting packets"), 1 },
    { "tacacs-authorization", o_bool, &use_authorize,
      STR("Use TACACS+ to authorize for PPP"), 1 },
    { "tacacs-server", o_special, tacacs_get_server,
      STR("TACACS+ server IP address") },
    { "tacacs-secret", o_string, tac_secret_buffer,
      STR("Key used to encrypt TACACS+ packets"),OPT_STATIC,NULL,MAXSECRETLEN},
    { NULL }
};

static int
tacacs_get_server(char **argv)
{
    struct in_addr addr;
    struct hostent *h;
    
    if (inet_aton(*argv, &addr) == 0) {
	h = gethostbyname(*argv);
	if (h == NULL) {
	    option_error("invalid TACACS+ server '%s'", *argv);
	    return 0;
	}
	memcpy((char*)&addr, h->h_addr, sizeof(addr));
    }

    tac_server = addr.s_addr;

    return 1;
}

static int
tacacs_check(void)
{
    int tac_fd;
    int ret;

    if (prev_pap_check_hook) {
	ret = prev_pap_check_hook();
	if (ret >= 0) {
	    return ret;
	}
    }
    
    if (!use_tacacs)
	return -1;

    if (tac_server == -1)
	return 0;

    tac_fd = tac_connect(&tac_server, 1);
    if (tac_fd < 0)
	return 0;
    
    close(tac_fd);

    return 1;
}
    
static int
tacacs_auth(char *t_user, char *t_passwd, char**t_msgp,
			struct wordlist **t_paddrs, struct wordlist **t_popts)
{
    int  tac_fd;
    char *msg;
    struct areply   arep;
    struct tac_attrib *attr;
    struct tac_attrib *attrentry;
    struct wordlist **pnextaddr;
    struct wordlist *addr;
    int addrlen;
    int ret;

    if (prev_pap_auth_hook) {
	ret = prev_pap_auth_hook(t_user, t_passwd, t_msgp, t_paddrs, t_popts);
	if (ret >= 0) {
	    return ret;
	}
    }
    
    if (!use_tacacs) return -1;

    *t_msgp = "TACACS+ server failed";
    *t_popts = NULL;

    /* start authentication */

    if (tac_server == -1)
	return 0;
    
    tac_fd = tac_connect(&tac_server, 1);
    if (tac_fd < 0)
	return 0;

    if (tac_authen_pap_send(tac_fd, t_user, t_passwd, tty) < 0)
	return 0;

    msg = tac_authen_pap_read(tac_fd);
    if (msg != NULL) {
	*t_msgp = msg;
	return 0;
    }

    close(tac_fd);

    /* user/password is valid, now check authorization */
    if (use_authorize) {
	tac_fd = tac_connect(&tac_server, 1);
    	if (tac_fd < 0)
	    return 0;

	attr = NULL;
	tac_add_attrib(&attr, "service", "ppp");
	tac_add_attrib(&attr, "protocol", "ip");

	if (tac_author_send(tac_fd, t_user, tty, attr) < 0)
	    return 0;

	tac_author_read(tac_fd, &arep);
	if (arep.status != AUTHOR_STATUS_PASS_ADD
	        && arep.status != AUTHOR_STATUS_PASS_REPL) {
	    *t_msgp = arep.msg;
    	    return 0;
	}

	tac_free_attrib(&attr);
	close(tac_fd);

	/* Build up list of allowable addresses */
	*t_paddrs = NULL; /* Default to allow all */
	pnextaddr = t_paddrs;
	for (attrentry=arep.attr; attrentry!=NULL; attrentry=attrentry->next) {
	    if (strncmp(attrentry->attr, "addr=", 5) == 0) {
		addrlen = attrentry->attr_len - 5;

		/* Allocate a buffer for both the structure and the address */
		addr = (struct wordlist*)malloc(sizeof(struct wordlist)
						+ addrlen + 1);
		if (addr == NULL)
		    novm("TACACS+ address");

		addr->word = (char*)(addr+1);
		strncpy(addr->word, attrentry->attr+5, addrlen);
		addr->word[addrlen] = '\0';

		addr->next = NULL;
		*pnextaddr = addr;
		pnextaddr = &addr->next;
	    }
	}

	tac_free_attrib(&arep.attr);
    }
    
    *t_msgp = "Login succeeded";
    syslog(LOG_INFO,"TACACS+ login succeeded for %s", t_user);

    authorized = 1;

    return 1;
}


static void
accounting_start(void)
{
    int  tac_fd;
    char *phone;
    char *msg;
    struct tac_attrib   *attr;
    struct in_addr      peer_addr;
    char   buf[40];

    if (prev_ip_up_hook) {
	prev_ip_up_hook();
    }
    
    if (use_tacacs && use_account && authorized) {
	authorized = 0;
	logged_in = 1;

	if (tac_server == -1)
	    return;
    
	tac_fd = tac_connect(&tac_server, 1);
	if (tac_fd < 0)
	    return;

	/* start accounting */
	attr = NULL;

	sprintf(buf, "%lu", time(0));
	tac_add_attrib(&attr, "start_time", buf);

	sprintf(buf, "%hu", task_id);
	tac_add_attrib(&attr, "task_id", buf);

	phone = getenv("CALLER_ID");
	if (!phone)
	    phone = "Unknow";
	tac_add_attrib(&attr, "phone_#", phone);

	tac_add_attrib(&attr, "service", "ppp");
	tac_add_attrib(&attr, "protocol", "ip");

	peer_addr.s_addr = ipcp_hisoptions[0].hisaddr;
	sprintf(buf, "%s", inet_ntoa(peer_addr));

	tac_account_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, peer_authname, tty, buf, attr);

	msg = tac_account_read(tac_fd);
	if (msg != NULL)
	    syslog(LOG_ERR,"TACACS+ start accounting failed: %s", msg);

	close(tac_fd); 
	tac_free_attrib(&attr);
    }
}

static void
accounting_stop(void)
{
    int  tac_fd;
    char *msg;
    struct tac_attrib *attr;
    struct in_addr      peer_addr;
    char   buf[40];

    if (prev_ip_down_hook) {
	prev_ip_down_hook();
    }
    
    if (use_tacacs && use_account && logged_in) {
	logged_in = 0;

	if (tac_server == -1)
	    return;
    
	tac_fd = tac_connect(&tac_server, 1);
	if (tac_fd < 0)
	    return;

	/* stop accounting */
	attr = NULL;

	sprintf(buf, "%lu", time(0));
	tac_add_attrib(&attr, "stop_time", buf);
	sprintf(buf, "%hu", task_id);
	tac_add_attrib(&attr, "task_id", buf);
	if (link_stats_valid) {
	    sprintf(buf, "%d", link_stats.bytes_out);
	    tac_add_attrib(&attr, "bytes_out", buf);
	    sprintf(buf, "%d", link_stats.bytes_in);
	    tac_add_attrib(&attr, "bytes_in", buf);
	    sprintf(buf, "%d", link_connect_time);
	    tac_add_attrib(&attr, "elapsed_time", buf);
	    peer_addr.s_addr = ipcp_hisoptions[0].hisaddr;
	    sprintf(buf, "%s", inet_ntoa(peer_addr));
	}
	
	tac_account_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, peer_authname, tty, buf, attr);
	
	msg = tac_account_read(tac_fd);
	if (msg != NULL)
	    syslog(LOG_ERR,"TACACS+ stop accounting failed: %s\n", msg);
	
	close(tac_fd);
	tac_free_attrib(&attr);
    }
}

void
#ifdef EMBED
tacacs_plugin_init(void)
#else
plugin_init(void)
#endif
{
    char *ptr;

    /* Prevent initialising twice */
    if (!plugin_loaded) {
	plugin_loaded = 1;

	syslog(LOG_INFO,"TACACS+ 0.3 Init functions");
	
	/* Initialize global variables */
	magic_init();
	task_id = (short)magic();
	
	ptr = devnam;
	if (strncmp(ptr, "/dev/", 5) == 0)
	    ptr += 5;
	strncpy(tty, ptr, 31);
	tty[31] = '\0';
	
	/* set variables in libtac */
	tac_secret = tac_secret_buffer;
	tac_encryption = 1;
	
	/* install pppd hooks */
	add_options(tacacs_options);
	
	prev_pap_check_hook = pap_check_hook;
	pap_check_hook = tacacs_check;
	
	prev_pap_auth_hook = pap_auth_hook;
	pap_auth_hook = tacacs_auth;
	
	prev_ip_up_hook = ip_up_hook;
	ip_up_hook = accounting_start;
	
	prev_ip_down_hook = ip_down_hook;
	ip_down_hook = accounting_stop;
    }
}
