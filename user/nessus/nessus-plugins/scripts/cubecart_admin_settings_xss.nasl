#
# (C) Tenable Network Security
#


if (description) {
  script_id(17260);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0606", "CVE-2005-0607");
  script_bugtraq_id(12658);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13810");
    script_xref(name:"OSVDB", value:"14213");
    script_xref(name:"OSVDB", value:"14214");
    script_xref(name:"OSVDB", value:"14215");
    script_xref(name:"OSVDB", value:"14216");
    script_xref(name:"OSVDB", value:"14217");
    script_xref(name:"OSVDB", value:"14218");
    script_xref(name:"OSVDB", value:"14219");
    script_xref(name:"OSVDB", value:"14220");
    script_xref(name:"OSVDB", value:"14221");
  }

  name["english"] = "CubeCart settings.inc.php Cross-Site Scripting and Path Disclosure Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple issues. 

Description :

According to its banner, the version of CubeCart installed on the
remote host suffers from multiple cross-site scripting and path
disclosure vulnerabilities due to a failure to sanitize user input in
'admin/settings.inc.php', which is used by various scripts.

See also : 

http://lostmon.blogspot.com/2005/02/cubecart-20x-multiple-variable-xss.html
http://www.cubecart.com/site/forums/index.php?showtopic=6032

Solution : 

Upgrade to CubeCart 2.0.6 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks version of CubeCart";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # If it's CubeCart 2.0.0 - 2.0.5, there's a problem.
  if (ver =~ "^2\.0\.[0-5]") security_note(port);
}
