#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22364);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-4784", "CVE-2006-4785", "CVE-2006-4786");
  script_bugtraq_id(19995, 20085);

  script_name(english:"Moodle < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Checks if Moodle's jumpto.php requires a sesskey");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The installed version of Moodle fails to sanitize user-supplied input
to a number of parameters and scripts.  An attacker may be able to
leverage these issues to launch SQL injection and cross-site scripting
attacks against the affected application. 

See also :

http://www.securityfocus.com/archive/1/446227/30/0/threaded
http://docs.moodle.org/en/Release_Notes#Moodle_1.6.2

Solution :

Upgrade to Moodle version 1.6.2 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("moodle_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Request a redirect.
  xss = "nessus.php?";
  req = http_get(
    item:string(dir, "/course/jumpto.php?jump=", urlencode(str:xss)), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # we get a session cookie for Moodle and...
    "MoodleSession=" >< res &&
    # we're redirected
    string("location.replace('", xss, "')") >< res
  ) security_warning(port);
}
