#
# (C) Tenable Network Security
#


if (description) {
  script_id(18639);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2106");
  script_bugtraq_id(14110);

  name["english"] = "Drupal Arbitrary PHP Code Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
arbitrary PHP code injection. 

Description :

The version of Drupal installed on the remote host, according to its
version number, allows attackers to embed arbitrary PHP code when
submitting a comment or posting. Note that successful exploitation
requires that public comments or postings be allowed in Drupal.

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=112015287827452&w=2
http://drupal.org/drupal-4.6.2

Solution : 

Upgrade to Drupal version 4.5.4 / 4.6.2 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
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
    # it's an affected version (ie, 4.5.0 - 4.5.3; 4.6.0 - 4.6.1) or...
    ver =~ "^4\.(5\.[0-3]|6\.[01])" ||
    # the version is unknown and report_paranoia is set to paranoid
    ("unknown" >< ver && report_paranoia > 1)
  ) {
    security_warning(port);
    exit(0);
  }
}
