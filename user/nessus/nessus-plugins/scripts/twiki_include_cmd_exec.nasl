#
# (C) Tenable Network Security
#


if (description) {
  script_id(20068);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3056");
  script_bugtraq_id(14960);

  name["english"] = "TWiki INCLUDE Function Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server includes a CGI script that allows for arbitrary
shell command execution. 

Description :

According to its banner, the installed version of TWiki allows an
attacker, by manipulating input to the 'rev' parameter, to execute
arbitrary shell commands on the remote host subject to the privileges
of the web server user id. 

See also : 

http://twiki.org/cgi-bin/view/Codev/SecurityAlertExecuteCommandsWithInclude

Solution : 

Apply the appropriate hotfix listed in the vendor advisory. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for INCLUDE function command execution vulnerability in TWiki";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("twiki_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0);
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if ( ver =~ "^(0[123] Sep 2004|01 Feb 2003)$") {
    security_warning(port);
    exit(0);
  }
}
