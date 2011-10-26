#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10078);
 script_version ("$Revision: 1.21 $");

 name["english"] = "Microsoft Frontpage 'authors' exploits";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server appears to be running with
Frontpage extensions and lets the file 'authors.pwd'
to be downloaded by everyone.

This is a security concern since this file contains
sensitive data.

Solution : Contact Microsoft for a fix.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Microsoft Frontpage extensions";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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

sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);
res = is_cgi_installed_ka(item:"/_vti_pvt/authors.pwd", port:port);
if ( res ) security_warning(port);
