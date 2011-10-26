#
# (C) Tenable Network Security
#


if (description) {
  script_id(18571);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2320");
  script_bugtraq_id(14072);

  name["english"] = "WebCalendar assistant_edit.php Unauthorized Access Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server has a PHP script that allows unauthorized
access. 

Description :

The remote version of WebCalendar fails to restrict access to the
script 'assistant_edit.php'.  An attacker can use this script to
change assistants and to display all users in the system even when the
'Public access can view other users' setting has been disabled. 

See also :

http://sourceforge.net/project/shownotes.php?release_id=328057

Solution : 

Upgrade to WebCalendar 1.0.0 or newer.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for assistant_edit.php unauthorized access vulnerability in WebCalendar";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("webcalendar_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to call the script directly.
  req = http_get(item:string(dir, "/assistant_edit.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get the page -- the fix redirects
  # people to the month view (or whatever the startview is).
  if ('<FORM ACTION="assistant_edit_handler.php"' >< res) {
    security_note(port);
    exit(0);
  }
}
