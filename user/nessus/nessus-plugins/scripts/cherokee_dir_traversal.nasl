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
 script_id(15621);
 script_version("$Revision: 1.4 $");

 script_cve_id("CVE-2001-1432");
 script_bugtraq_id(3772);

 name["english"] = "Cherokee directory traversal flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to directory
traversal flaw when appending a '../' sequence to the web request.

Additionally, this version fails to drop root privileges after it binds 
to listen port.

Remote attacker can then submit specially crafted web request to 
browse any file on the server with root privileges.

Solution : Upgrade to Cherokee 0.2.8 or newer
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
if(ereg(pattern:"^Server:.*Cherokee/0\.([01]\.|2\.[0-7])[^0-9]", string:serv))
 {
   security_hole(port);
 }
