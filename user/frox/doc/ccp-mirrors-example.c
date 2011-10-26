#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/*
 * This is a CCP for frox. The sample code is licensed under the GPL
 * as seen in COPYING. This CCP tries to implement transparent
 * redirection of ftp clients to local mirrors. The mirrors are
 * defined in..., well the mirrors structure. First field is the host
 * name of the remote server, second is the host name of the mirror,
 * and third is the path on the mirror which corresponds to root on
 * the server.
 *
 * I try to make the client unaware that there are directories below
 * them. "cdup", and "cd .." are blocked, and the hidden part of the
 * path is stripped from the reply to a "pwd" request. I haven't
 * tested extensively though. Also I suspect bad things will happen if
 * one of the mirror servers doesn't log you in to the root directory.
 *
 * I suspect that this program would be a third the length if it were
 * written in Perl. :) */

/*
 * Basically if we read an "I" it is followed by session initialisation
 * data, a "C" and it is followed by a message from the client, and an
 * "S" and it is followed by a message from the server.
 *
 * If we write an "X" frox will forward on the message it just sent
 * us. Anything else and we are responsible for doing it ourselves. If
 * we write "S ..." we send a message to the server, and "C ....." a
 * message to the client. "L ......" sends a log message, and should be
 * followed by an action. "Q" tells frox to exit this session.
 *
 * We can't use "C" or "S" to reply to an "I", but we can reply with 
 * "R ......." where the R is followed by an IP address. Frox will redirect
 * the session to this IP.
*/

struct mirror_table{
	const char *remote;
	const char *mirror;
	const char *dir;
	
	struct in_addr *r_addrs, *m_addrs;
	int n_raddrs, n_maddrs;

};

struct mirror_table mirrors[] = {
	{ "ftp.debian.org", "localhost", "/pub/mirrors/debian" },
	{ "ftp.tucows.com", "ftp.mirror.localnet", "/pub/mirrors/tucows" },
        { 0, 0, 0}
};

char *edit_cmds[] = {"SMNT", "APPE", "RNFR", "RNTO", "DELE", "RMD",
		     "MKD", "RETR", "SIZE", "STOR", "LIST", "NLST",
		     "STAT", "CWD", "CDUP", 0};
int edit_codes[] = {257, 150, 0};
int m_no=-1;

#define BLEN 1024 /*Must be greater than frox's MAX_LINE_LEN*/
#define ccp_command(a, b) printf("S %s %s\n", a, b)
#define ccp_message(a, b) printf("C %d %s\n", a, b)
#define ccp_passthrough() printf("X\n")
#define ccp_redirect(a)   printf("R %s\n", a)
#define ccp_log(a)        printf("L %s\n", a)
#define ccp_quit()        printf("Q\n")

int init_mirrors(void);
int check_ip(char *buf);
void change_ip(void);
int edit_cmd(char *buf);
int edit_msg(char *buf);
int confirm_cwd(void);
int allow_path(char *arg, int *l);

int main(void)
{
	char buf[BLEN];

	if(init_mirrors()==-1) {
		ccp_log("CCP unable to resolve mirrors list");
		ccp_quit();
		return -1;
	}

	while(fgets(buf, 1023, stdin)) {
		switch(*buf) {
		case 'C':
			if(m_no<0) ccp_passthrough();
			else edit_cmd(buf);
			break;
		case 'S':
			if(m_no<0) ccp_passthrough();
			else edit_msg(buf);
			break;
		case 'I':
			m_no = check_ip(buf);
			if(m_no<0) ccp_passthrough();
			else change_ip();
			break;
		}
		fflush(stdout);
	}
	return 0;
}

int init_mirrors(void)
{
	int i, j;
	char **p;
	struct hostent *hostinfo;

	for(i=0;mirrors[i].remote; i++) {
		hostinfo = gethostbyname(mirrors[i].remote);
		if (!hostinfo || hostinfo->h_addrtype != AF_INET)
			return(-1);

		for(p=hostinfo->h_addr_list, j=0; *p; p++, j++);
		mirrors[i].r_addrs=malloc(sizeof(struct in_addr) * j);
		mirrors[i].n_raddrs=j;
		for(j=0;j<mirrors[i].n_raddrs;j++) {
			mirrors[i].r_addrs[j] = *((struct in_addr *)
						hostinfo->h_addr_list[j]);
		}

		hostinfo = gethostbyname(mirrors[i].mirror);
		if (!hostinfo || hostinfo->h_addrtype != AF_INET)
			return(-1);

		for(p=hostinfo->h_addr_list, j=0; *p; p++, j++);
		mirrors[i].m_addrs=malloc(sizeof(struct in_addr) * j);
		mirrors[i].n_maddrs=j;
		for(j=0;j<mirrors[i].n_maddrs;j++) {
			mirrors[i].m_addrs[j] = *((struct in_addr *)
						hostinfo->h_addr_list[j]);
		}
	}
	return 0;
}

int check_ip(char *buf)
{
	int i, j;
	char tmp[20];
	struct in_addr match;

	sscanf(buf, "I %*s %s %*s", tmp);
	inet_aton(tmp, &match);
	for(i=0;mirrors[i].remote; i++) {
		for(j=0;j<mirrors[i].n_raddrs;j++) {
			if(match.s_addr==mirrors[i].r_addrs[j].s_addr)
				return i;
		}
	}
	return -1;
}

void change_ip(void)
{
	char buf[BLEN];
	int j;

	j = (int) (mirrors[m_no].n_maddrs * rand()/(RAND_MAX+1.0));
	sprintf(buf, "Redirecting connection for %s to local mirror",
		mirrors[m_no].remote);
	ccp_log(buf);
	ccp_redirect(inet_ntoa(mirrors[m_no].m_addrs[j]));
}

/* If command does not involve a path and does not change directory,
   send it through unchanged. Otherwise check the path to see it
   doesn't attempt to "../" above our fake root directory. Finally we
   edit any absolute or empty paths by prepending the path of the fake
   root directory.*/
int edit_cmd(char *buf)
{
	static int level=0, inroot=1;
	int newlevel=level;
	char *cmd, *arg, **p, tmp[BLEN];

	cmd=buf+2;
	for(arg = cmd;*arg!=' ';arg++);
	*arg++=0;
	if(strlen(arg)>0)
		arg[strlen(arg)-1]=0; /*Strip trailing \n*/

	for(p=edit_cmds;*p;p++)
		if(!strcmp(*p, cmd)) break;
	if(!*p) {
		ccp_passthrough();
		return 0;
	}

	if(!allow_path(arg, &newlevel)) {
		ccp_message(550, "No such directory");
		return -1;
	}

	if(!strcmp(cmd, "CDUP")) {
		if(!level) {
			ccp_message(550, "No such directory");
			return -1;
		}
		newlevel=level-1;
	}

	/*We need to prepend the fake root path for absolute paths,
          for relative paths where we have not yet done a chdir into
          the fake root tree, and for empty paths where the server
          will interpret this as meaning the current directory*/
	if((!inroot && *arg!='/') || (!strcmp(cmd, "STAT") && *arg==0)) {
		ccp_passthrough();
	} else {
		strcpy(tmp, mirrors[m_no].dir);
		strcat(tmp, "/");
		strcat(tmp, arg);
		ccp_command(cmd, tmp);
	}

	if(!strcmp(cmd, "CDUP") || !strcmp(cmd, "CWD")) {
		if(confirm_cwd()) {
			level = newlevel;
			inroot = 0;
		}
	}

	return 1;
}

int allow_path(char *arg, int *l)
{
	char *p=arg;

	if(*p=='/') {
		*l=0;
		p++;
	}
	while(*p){
		if(!strncmp(p, "../", 3) || !strcmp(p, "..")) (*l)--;
		else (*l)++;
		if(*l<0) return 0;
		for(;*p && *p!='\n' && *p!='/'; p++);
		if(!*p) break;
		while(*++p=='/');
	}
	return 1;
}

int confirm_cwd(void)
{
	int code;
	char buf[BLEN];

	fflush(stdout);
	if(!fgets(buf, 1023, stdin))
		exit(0);
	
	if(*buf != 'S') {
		ccp_log("L CCP was expecting an S. Sorry - exiting");
		ccp_quit();
		exit(0);
	}
	code=atoi(buf+2);
	
	ccp_passthrough();

	return (code<300);
}

int edit_msg(char *buf)
{
	int *cp, i, code;
	char *cmd, *arg, *p;

	cmd=buf+2;
	for(arg = cmd;*arg!=' ';arg++);
	*arg++=0;
	if(strlen(arg)>0)
		arg[strlen(arg)-1]=0; /*Strip trailing \n*/
	code=atoi(cmd);
	
	for(cp=edit_codes;*cp;cp++)
		if(*cp==code) break;
	if(!*cp) {
		ccp_passthrough();
		return 0;
	}

	p=strstr(arg, mirrors[m_no].dir);
	if(!p) {
		ccp_passthrough();
		return 0;
	}

	i=strlen(mirrors[m_no].dir);
	if(*(p+i)!='/') {
		p++;
		i--;
	}
	memmove(p, p+i, strlen(p+i)+1);

	ccp_message(code, arg);
	return 1;
}
