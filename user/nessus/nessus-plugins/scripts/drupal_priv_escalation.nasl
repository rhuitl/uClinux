#
# (C) Tenable Network Security
#


if (description) {
  script_id(18641);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1871");
  script_bugtraq_id(13852);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"17028");

  name["english"] = "Drupal Privilege Escalation Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to a
privilege escalation issue. 

Description :

According to its banner, the version of Drupal installed on the remote
host allows attackers to gain elevated privileges, provided public
registration is enabled, due to an improperly-implemented input check. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2005-06/0010.html

Solution : 

Upgrade to Drupal version 4.4.3 / 4.5.3 / 4.6.1 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks version of Drupal";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # There's a problem if...
  if (
    # it's an affected version (ie, 4.4.0-4.4.2; 4.5.0-4.5.2; 4.6.0) or...
    ver =~ "^4\.(4\.[0-2]|5\.[0-2]|6\.0)" ||
    # the version is unknown and report_paranoia is set to paranoid
    ("unknown" >< ver && report_paranoia > 1)
  ) {
    security_note(port);
    exit(0);
  }
}
