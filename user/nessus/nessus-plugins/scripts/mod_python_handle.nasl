#
# This script was written by Thomas Reinke <reinke@securityspace.com>,
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10947);
 script_bugtraq_id(4656);
 script_cve_id("CVE-2002-0185");
 script_version("$Revision: 1.11 $");
 
 name["english"] = "mod_python handle abuse";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the Apache mod_python module which
is version 2.7.6 or older.

These versions allow a module which is indirectly imported
by a published module to then be accessed via the publisher,
which allows remote attackers to call possibly
dangerous functions from the imported module. 

Solution : Upgrade to a newer version.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Python";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Thomas Reinke");
 family["english"] = "Web Servers";
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

 serv = strstr(banner, "Server");
 if(ereg(pattern:".*mod_python/(1.*|2\.([0-6]\..*|7\.[0-6][^0-9])).*", string:serv))
 {
   security_hole(port);
 }
}
