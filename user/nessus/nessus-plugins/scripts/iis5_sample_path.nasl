#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10573);
 script_version("$Revision: 1.12 $");
 name["english"] = "IIS 5.0 Sample App reveals physical path of web root";
 script_name(english:name["english"]);
 
 desc["english"] = "A sample application shipped with IIS 5.0 discloses 
the physical path of the web root. An attacker can use this information 
to make more focused attacks.

Solution: Always remove sample applications from productions servers. 
In this case, remove the entire /iissamples folder.
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "IIS 5.0 Sample App reveals physical path of web root";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Matt Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

res = is_cgi_installed_ka(item:"/iissamples/sdk/asp/interaction/ServerVariables_Jscript.asp", port:port);
if(res)security_warning(port);
