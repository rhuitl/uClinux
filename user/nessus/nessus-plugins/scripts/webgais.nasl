#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10300); 
 script_bugtraq_id(2058);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0176");
 
 name["english"] = "webgais";
 name["francais"] = "webgais";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
code execution. 

Description :

The 'webgais' CGI is installed.  This CGI may let an attacker execute
arbitrary commands with the privileges of the http daemon (usually root
or nobody). 

See also :

http://archives.neohapsis.com/archives/bugtraq/1997_3/0057.html

Solution : 

Remove this CGI.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/webgais";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "webmirror.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"webgais", port:port);
if(res)security_hole(port);
