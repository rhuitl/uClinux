
/*

    File: pop3.h
  
    Copyright (C) 1999, 2004, 2005 Wolfgang Zekoll <wzk@quietsche-entchen.de>
  
    This software is free software; you can redistribute it and/or modify
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
 
#ifndef _POP3_INCLUDED
#define	_POP3_INCLUDED


#define	POP3_CLIENTTIMER	25
#define	POP3_TIMEOUT		600

#define	REDIR_NONE		0
#define	REDIR_ACCEPT		1
#define	REDIR_FORWARD		2
#define	REDIR_FORWARD_ONLY	3

#define	PIDFILE			"/var/run/pop3.proxy.pid"
#define	SPAMC			"/usr/bin/spamc -c"


extern char *program;
extern char progname[80];
extern int debug;
extern int extendedlog;



typedef struct _config {
    char	srcip[200];
    char	server[200];
    char	ident[200];

    int		redirmode;
    int		selectserver;
    char	defaultserver;
    char	*serverlist;
    int		timeout;

    int		scanmail;
    struct {
	int	autodirectory;
	char	quarantine[200];
	char virusevent[200];
	} clamav;

    int		spamscan;
    struct {
	char	spamtag[40];
	char	cmd[200];
	} spamd;

    char	serverdelim[20];
    char	clientdir[200];

    char	acp[200];

    struct {
	char	name[40];
	unsigned int uid, gid;
	} user;
    } config_t;



typedef struct _string {
    int		len, max;
    char	*string;
    } string_t;


typedef struct _bio {
    int		fd;

    int		here, len;
    char	buffer[512];
    } bio_t;


typedef struct _channel {
    char	name[200];

    char	hostname[200];
    unsigned int port;
 
    bio_t	bio;
    } channel_t;


typedef struct _pop3 {
    config_t	*config;

    peer_t	i;

    int		state;
    struct {
	char	username[200];
	char	password[80];

	char	name[200];
	char	ipnum[100];
	bio_t	bio;
	} client;

    struct {
	char	username[80];
	char	password[80];
	} local;

    channel_t	server;

    struct {
	char	ipnum[100];
	unsigned int port;
	} origdst;

    struct {
	char	adress[80];
	unsigned int port;
	char	version[200];
	bio_t	bio;
	string_t header;
	} clamav;


    unsigned long lasttimer;
    char	spoolfile[200];
    unsigned long size;
    char	logfile[200];
    unsigned long started;
    } pop3_t;



extern int printerror(int rc, char *type, char *format, ...);
extern int writestatfile(pop3_t *x, char *status);

extern int getc_fd(pop3_t *x, bio_t *bio, int clienttimer);
extern char *readline_fd(pop3_t *x, bio_t *bio, char *line, int size, int clienttimer);

extern char *cfgets(pop3_t *x, char *line, int size);
extern int cfputd(pop3_t *x, char *line);
extern int cfputs(pop3_t *x, char *line, int log);
extern char *sfgets(pop3_t *x, char *line, int size, int clienttimer);
extern int sfputs(pop3_t *x, char *line);

extern int settmpdir(char *dir);
extern int getclamversion(pop3_t *x);
extern int doscanmail(pop3_t *x);
extern int proxy_request(config_t *config);


#endif

