#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15617);
 script_cve_id("CVE-2004-1097");
 script_bugtraq_id(11574);
 script_version("$Revision: 1.5 $");
 name["english"] = "Cherokee auth_pam format string vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to a format string
attack when processing authentication requests using auth_pam.

Solution : Upgrade to Cherokee 0.4.17.1  or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Cherokee";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.([0-9]|1[0-7]))[^0-9.]", string:serv))
 {
   security_hole(port);
 }
