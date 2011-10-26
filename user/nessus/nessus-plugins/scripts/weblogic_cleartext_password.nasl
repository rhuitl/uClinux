#
# (C) Tenable Network Security
#
# Ref : http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-30.jsp
#
#

if(description)
{
 script_id(11627);
 script_cve_id("CVE-2003-1224", "CVE-2003-1225");
 script_bugtraq_id(7563);
 script_version ("$Revision: 1.5 $");
 
 
 name["english"] = "WebLogic clear-text passwords";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running WebLogic 7.0 or 7.0.0.1.

There is a bug in this version which may allow a local attacker
to recover a WebLogic password if he can see the screen of the web logic
server.

Solutions : http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-30.jsp
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebLogic";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
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

banner = get_http_banner(port:port);

if (" Temporary Patch for CR104520" >< banner) exit(0);


if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  security_warning(port);
  exit(0);
}

