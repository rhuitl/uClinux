#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10592);
 script_bugtraq_id(2166);
 script_version ("$Revision: 1.15 $");

 name["english"] = "webdriver";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that may fail to restrict
access to an installed database. 

Description :

The remote host may be running Informix Webdriver, a web-to-database
interface.  If not configured properly, this CGI script may give an
unauthenticated attacker the ability to modify and even delete
databases on the remote host. 

*** Nessus relied solely on the presence of this CGI; it did not
*** try to determine if the installed version is vulnerable to 
*** that problem.

See also :

http://archives.neohapsis.com/archives/bugtraq/2001-01/0002.html
http://archives.neohapsis.com/archives/bugtraq/2001-01/0043.html

Solution : 

Consult the product documentation to properly configure the script.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Webdriver";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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

res = is_cgi_installed_ka(port:port, item:"webdriver");
if(res)security_warning(port);
