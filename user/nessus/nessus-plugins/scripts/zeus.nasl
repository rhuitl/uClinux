#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10327);
 script_bugtraq_id(977);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0149");
 
 name["english"] = "Zeus shows the content of the cgi scripts";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server is affected by an informtion disclosure flaw. 

Description :

The remote host is running the Zeus WebServer.

Version 3.1.x to 3.3.5 of this web server are vulnerable to a bug
that allows an attacker to view the source code of CGI scripts. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2000-02/0072.html

Solution : 

Upgrade to Zeus 3.3.5a or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Zeus";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zeus");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(banner)
{ 
  if(egrep(pattern:"Server *:.*Zeus/3\.[1-3][^0-9]", string:banner))
   security_warning(port);
}
