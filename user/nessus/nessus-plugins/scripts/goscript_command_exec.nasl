#
# (C) Tenable Network Security
#
# osvdb value submitted by David Maciejak

  desc = "
The remote host is running a version of Pete Stein's Goscript
which is vulnerable to a remote command execution flaw.

An attacker, exploiting this flaw, would only need access to 
the webserver.
 
Solution : Upgrade to latest version of Goscript 

See also : http://www.securityfocus.com/bid/10853 
 
Risk factor : High";


if (description) {
  script_id(14237);
  script_bugtraq_id(10853);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"8935");
  script_version ("$Revision: 1.6 $");

  name["english"] = "Goscript command execution";
  script_name(english:name["english"]);
 
  script_description(english:desc);
 
  summary["english"] = "Goscript command execution detection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) Tenable Network Security");
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_check_remote_code (
			check_request:"/go.cgi|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
