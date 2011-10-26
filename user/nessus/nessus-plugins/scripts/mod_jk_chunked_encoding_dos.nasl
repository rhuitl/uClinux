#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11519);
 script_bugtraq_id(6320);

 script_version("$Revision: 1.7 $");
 
 name["english"] = "mod_jk chunked encoding DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the Apache mod_jk module which
is older than version 1.2.1

There is a bug in these versions which may allow an 
attacker to use chunked encoding requests to desynchronize
Apache and Tomcat, and therefore prevent the remote web site
from working properly.

*** As Nessus solely relied on the banner of the remote
*** host to issue this alert, this might be a false positive

Solution : Upgrade to mod_jk 1.2.1 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of mod_jk";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 serv = strstr(banner, "Server:");
 
 if(ereg(pattern:".*mod_jk/1\.([0-1]\..*|2\.0)", string:serv))
 {
   security_warning(port);
 }
}
