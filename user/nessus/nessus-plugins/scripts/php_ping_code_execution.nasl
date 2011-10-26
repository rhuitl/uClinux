#
# (C) Tenable Network Security
#

  desc = "
Synopsis :

The remote web server contains a PHP script that allows for arbitrary
command execution.

Description :

The remote host appears to be running php-ping .php from TheWorldsEnd.NET.
The remote version of this script does not properly sanitize count parameter
and allows attackers to execute arbitrary commands or read arbitrary files
on the remote host subject to the privileges of the web server user id. 

Solution : 

Remove or update the affected scripts.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
  script_id(11966);
  script_bugtraq_id(9309);
  script_version("$Revision: 1.9 $");
  name["english"] = "php-ping Count Parameter Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc);
 
  summary["english"] = "Detect PHP Ping Code Execution";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);

http_check_remote_code (
			extra_check:"</body>Ping Output:<br><pre>",
			check_request:"/php-ping.php?host=test&submit=Ping!&count=1|id||",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
