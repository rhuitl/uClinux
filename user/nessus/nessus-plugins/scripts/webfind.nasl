#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10475);
 script_bugtraq_id(1487);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0622");
 name["english"] = "Buffer overflow in WebSite Professional's webfind.exe";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is affected by a
buffer overflow flaw. 

Description :

The 'webfind.exe' CGI script on the remote host is vulnerable to a
buffer overflow when given a too long 'keywords' argument.  This
problem allows an attacker to execute arbitrary code as root on this
host. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2000-07/0268.html

Solution : 

Upgrade to WebSite Professional 2.5 or delete this CGI.

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Buffer overflow attempt";
 script_summary(english:summary["english"]);
 
 # This test is harmless
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/websitepro");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
req = string(dir, "/webfind.exe?keywords=", crap(10));
req = http_get(item:req, port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 ", string:r))
{
 # No keep alive here
 req = string(dir, "/webfind.exe?keywords=", crap(2000));
 req = http_get(item:req, port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(!r)security_hole(port);
 }
}
