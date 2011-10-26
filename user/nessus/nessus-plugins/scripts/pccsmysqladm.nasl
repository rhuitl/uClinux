#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 name["english"] = "PCCS-Mysql User/Password Exposure";
 
 script_name(english:name["english"]);
 script_id(10783);
 script_bugtraq_id(1557);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2000-0707");
 
 desc["english"] = "
It is possible to read the include file of PCCS-Mysql, 
dbconnect.inc on the remote server.

This include file contains information such as the
username and password used to connect to the database.

Solution:
Versions 1.2.5 and later are not vulnerable to this issue.
A workaround is to restrict access to the .inc file.

Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Checks for dbconnect.inc";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
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
res = is_cgi_installed_ka(port:port, item:"/pccsmysqladm/incs/dbconnect.inc");
if( res )security_hole(port);
