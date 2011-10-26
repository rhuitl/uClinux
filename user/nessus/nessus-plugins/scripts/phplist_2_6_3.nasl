#
# (C) Tenable Network Security
#


if (description) {
  script_id(17259);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(11545);

  script_name(english:"Multiple Vulnerabilities in PHPlist <= 2.6.3");
  script_summary(english:"Checks version of PHPlist");

  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

According to its banner, the version of PHPlist installed on the
remote host is prone to arbitrary command execution as well
as information disclosure vulnerabilities.

See also :

http://tincan.co.uk/?lid=851

Solution : 

Upgrade to PHPlist 2.6.4 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("phplist_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phplist"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Versions 2.6.3 and older are vulnerable.
  if (ver =~ "^([01]\..*|2\.([0-5]\..*|6\.[0-3]))") {
    security_hole(port);
    exit(0);
  }
}
