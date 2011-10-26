#
# (C) Tenable Network Security
#


if (description) {
  script_id(19590);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2837");
  script_bugtraq_id(14732);

  name["english"] = "WebGUI < 6.7.3 Multiple Command Execution Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
code execution. 

Description :

The remote host is running WebGUI, a content management system from
Plain Black Software. 

According to its banner, the installed version of WebGUI on the remote
host fails to sanitize user-supplied input to various sources before
using it to run commands.  By leveraging these flaws, an attacker may
be able to execute arbitrary commands on the remote host within the
context of the affected web server userid. 

See also : 

http://www.plainblack.com/getwebgui/advisories/security-exploit-found-in-6.x-versions

Solution : 

Upgrade to WebGUI 6.7.3 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple command execution vulnerabilities in WebGUI < 6.7.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Get the initial page.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  if (
    egrep(string:res, pattern:'<meta name="generator" content="WebGUI 6\\.([1-6]\\..*|7\\.[0-2])"') ||
    egrep(string:res, pattern:'^ +<!-- WebGUI 6\\.([1-6]\\..*|7\\.[0-2]) -->')
  ) {
    security_hole(port);
  }
}
