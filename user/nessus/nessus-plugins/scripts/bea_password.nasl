#
# Written by Astharot <astharot@zone-h.org>
#
# Reference: http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04_51.00.jsp
#
# UNTESTED

if(description)
{
 script_id(12043);
 script_cve_id("CVE-2004-1757");
 script_bugtraq_id(9501);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "BEA WebLogic Operator/Admin Password Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running WebLogic.

BEA WebLogic Server and WebLogic Express are reported prone to a vulnerability 
that may result in the disclosure of Operator or Admin passwords. An attacker 
who has interactive access to the affected managed server, may potentially 
exploit this issue in a timed attack to harvest credentials when the managed 
server fails during the boot process. 

Solution : http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04_51.00.jsp
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebLogic";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Astharot");
 family["english"] = "CGI abuses";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/" + port  + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);

banner = get_http_banner(port:port);

if ("Temporary Patch for CR127930" >< banner) exit(0);


if (egrep(pattern:"^Server:.*WebLogic ([6-8]\..*)", string:banner))
{
  security_warning(port);
}

