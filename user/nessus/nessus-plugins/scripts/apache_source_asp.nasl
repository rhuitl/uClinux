#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10480);
 script_bugtraq_id(1457);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0628");
 name["english"] = "Apache::ASP source.asp";
 script_name(english:name["english"]);
 
 desc["english"] = "
The file /site/eg/source.asp is present.

This file comes with the Apache::ASP package and allows anyone to write to files in the
same directory.

An attacker may use this flaw to upload his own scripts and execute arbitrary commands
on this host.

Solution : Upgrade to Apache::ASP 1.95
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /site/eg/source.asp";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
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

if ( ! get_port_state(port) ) exit(0);

sig = get_kb_item("www/hmap/"  + port  + "/description");
if ( sig && "Apache" >!< sig ) exit(0);


res = is_cgi_installed_ka(port:port, item:"/site/eg/source.asp");
if( res )
{
 security_hole(port);
}
