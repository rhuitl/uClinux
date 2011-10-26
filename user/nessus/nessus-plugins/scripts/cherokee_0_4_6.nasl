#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: <vnull@pcnet.com.pl>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15620);
 script_cve_id("CVE-2003-1198");
 script_bugtraq_id(9345);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:3306);

 script_version("$Revision: 1.3 $");
 name["english"] = "Cherokee POST request DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to remote denial 
of service vulnerability when handling a specially-crafted HTTP 
'POST' request.

An attacker may exploit this flaw to disable this service remotely.

Solution : Upgrade to Cherokee 0.4.7 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Cherokee";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Denial of Service";
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
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.[0-6])[^0-9]", string:serv))
 {
   security_hole(port);
 }
