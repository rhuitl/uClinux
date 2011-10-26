#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a web-based calendar application
written in PHP. 

Description :

This script detects whether the remote host is running WebCalendar and
extracts version numbers and locations of any instances found. 

WebCalendar is an open-source web calendar application written in PHP. 

See also : 

http://webcalendar.sourceforge.net/

Risk factor : 

None";


if (description) {
  script_id(18572);
  script_version("$Revision: 1.3 $");

  script_name(english:"WebCalendar Detection");
  script_summary(english:"Checks for presence of WebCalendar");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


# Search for WebCalendar.
installs = 0;
foreach dir (cgi_dirs()) {
  # Grab month.php.
  req = http_get(item:string(dir, "/month.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like WebCalendar...
  #
  # nb: not all sites have a banner so we have to look for 
  #     common elements instead.
  if (
    '<a class="dayofmonth" href="day.php?date=' >< res && 
    '<FORM ACTION="month.php" METHOD="GET" NAME="SelectMonth">' >< res
  ) {
    # Try to identify the version number from the banner, if present.
    pat = '<a title="WebCalendar v(.+) \\(.+\\)" id="programname" ';
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }

    # If that didn't work, try getting it from the changelog.
    if (isnull(ver)) {
      req = http_get(item:string(dir, "/ChangeLog"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = "^Version (.+) \\(";
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/webcalendar"),
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;

    # Scan for multiple installations only if "Thorough Tests" is checked.
    if (!thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (ver == "unknown") {
      info = string("An unknown version of WebCalendar was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("WebCalendar ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of WebCalendar were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = desc + '\n\nPlugin output :\n\n' + info;
  security_note(port:port, data:report);
}
