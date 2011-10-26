#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: GOBBLES advisory on December 29th, 2001.
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15622);
 script_cve_id("CVE-2001-1433");
 script_bugtraq_id(3771, 3773);

 script_version("$Revision: 1.3 $");
 name["english"] = "Cherokee remote command execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to remote
command execution due to a lack of web requests sanitization,
especially shell metacharacters.

Additionally, this version fails to drop root privileges after it binds 
to listen port.

A remote attacker may submit a specially crafted web request to 
execute arbitrary command on the server with root privileges.

Solution : Upgrade to Cherokee 0.2.7 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Cherokee";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
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
if(ereg(pattern:"^Server:.*Cherokee/0\.([01]\.|2\.[0-6])[^0-9]", string:serv))
 {
   security_hole(port);
 }
