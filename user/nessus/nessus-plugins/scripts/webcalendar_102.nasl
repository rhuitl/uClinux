#
# (C) Tenable Network Security
#


if (description) {
  script_id(20250);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-3949", "CVE-2005-3961", "CVE-2005-3982", "CVE-2005-3982");
  script_bugtraq_id(15606, 15608, 15662, 15673);
  script_xref(name:"OSVDB", value:"21216");
  script_xref(name:"OSVDB", value:"21217");
  script_xref(name:"OSVDB", value:"21218");
  script_xref(name:"OSVDB", value:"21219");
  script_xref(name:"OSVDB", value:"21383");

  script_name(english:"WebCalendar < 1.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in WebCalendar < 1.0.2");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote version of WebCalendar does not validate input to the 'id'
and 'format' parameters of the 'export_handler.php' script before
using it to overwrite files on the remote host, subject to the
privileges of the web server user id. 

In addition, the 'activity_log.php', 'admin_handler.php',
'edit_report_handler.php', 'edit_template.php' and
'export_handler.php' scripts are prone to SQL injection attacks and
the 'layers_toggle.php' script is prone to HTTP response splitting
attacks. 

See also : 

http://www.ush.it/2005/11/28/webcalendar-multiple-vulnerabilities/
http://www.securityfocus.com/archive/1/418286/30/0/threaded
https://sourceforge.net/tracker/index.php?func=detail&aid=1369439&group_id=3870&atid=303870

Solution : 

Upgrade to WebCalendar 1.0.2 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

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
#
# nb: this requires the application be configured to allow public access.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Make sure one of the affected scripts exists.
  req = http_get(item:string(dir, "/export_handler.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  #
  # nb: this appears in the case of an export error.
  if ('<span style="font-weight:bold;"' >< res) {
    # Pass a non-integer value for year; in a patched / fixed version
    # we'll get an error; otherwise, we'll get a calendar export.
    postdata = string(
      "format=ical&",
      "fromyear=nessus"
    );
    req = string(
      "POST ", dir, "/export_handler.php?plugin=", SCRIPT_NAME, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we're able to export the calendar.
    if ("Content-Type: text/calendar" >< res) {
      security_warning(port);
    }
  }
}
