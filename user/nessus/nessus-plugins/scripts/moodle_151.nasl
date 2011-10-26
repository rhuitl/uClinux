#
# (C) Tenable Network Security
# 


if (description) {
  script_id(18691);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-2247");
  script_bugtraq_id(14224);

  name["english"] = "Moodle < 1.5.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple problems. 

Description :

According to its banner, the version of Moodle installed on the remote
host suffers from several, as-yet unspecified, flaws. 

See also : 

http://moodle.org/doc/index.php?file=release.html

Solution : 

Upgrade to Moodle 1.5.1 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Moodle < 1.5.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("moodle_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.([0-4].*|5([^0-9]|$))") security_hole(port);
}
