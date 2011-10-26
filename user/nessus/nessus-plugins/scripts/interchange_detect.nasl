# Copyright 2002 by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# Note: this service is *not* a web server, but it looks like it for 
# find_service
# HEAD / HTTP/1.0	(the only request it seems to recognize)
# HTTP/1.0 200 OK
# Last-modified: [15/August/2002:17:41:40 +0200]
# Content-type: application/octet-stream
#
# GET / HTTP/1.0   (or anything else, even not HTTP: GROUMPF\r\n)
# HTTP/1.0 404 Not found
# Content-type: application/octet-stream
#
# / not a Interchange catalog or help file.
#

if(description)
{
 script_id(11128);
 script_bugtraq_id(5453);
 script_version ("$Revision: 1.8 $");

 name["english"] = "redhat Interchange";
 script_name(english:name["english"]);

 desc["english"] = "
It seems that 'Red Hat Interchange' ecommerce and dynamic 
content management application is running in 'Inet' mode 
on this port.

Versions 4.8.5 and earlier are flawed and may disclose 
contents of sensitive files to attackers.

** Nessus neither checked Interchange version nor tried 
** to exploit the vulnerability

Solution: Upgrade your software if necessary or configure it
for 'Unix mode' communication only.

Risk factor : None / Medium";
 
 script_description(english:desc["english"]);

 summary["english"] = "Redhat Interchange e-commerce application detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 script_family(english:"Service detection");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 7786);
 exit(0);
}

####

include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:7786);
if ( ! port ) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: string("NESSUS / HTTP/1.0\r\n\r\n"));
r = recv(socket: soc, length: 1024);
close(soc);

if ("/ not a Interchange catalog or help file" >< r) security_warning(port);

