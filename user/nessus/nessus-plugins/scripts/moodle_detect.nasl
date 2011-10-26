#
# (C) Tenable Network Security
# 


  desc["english"] = "
Synopsis :

The remote web server contains a content management system written in
PHP. 

Description :

The remote host is running Moodle, an open-source content management
system written in PHP. 

See also : 

http://moodle.org/

Risk factor :

None";


if (description) {
  script_id(18690);
  script_version("$Revision: 1.3 $");

  name["english"] = "Moodle Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects Moodle";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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


# Search for Moodle.
installs = 0;
foreach dir (cgi_dirs()) {
  # Request index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like Moodle...
  if (egrep(string:res, pattern:'<a [^>]*href="http://moodle\\.org/"[^>]*><img [^>]*src="pix/moodlelogo.gif"')) {
    # Try to extract the version number from the banner.
    pat = '<a title="moodle ([0-9][^"]+)" href="http://moodle\\.org/"';
    if (egrep(string:res, pattern:pat, icase:TRUE)) {
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # If that didn't work, try to get it from the release notes.
    if (isnull(ver)) {
      req = http_get(item:string(dir, "/lang/en/docs/release.html"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # nb: ignore patterns like "Moodle 1.5 (to be released shortly)"
      pat = "^<h2>Moodle (.+) \([0-9]";
      if (egrep(string:res, pattern:pat, icase:TRUE)) {
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = ver[1];
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/moodle"),
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
      info = string("An unknown version of Moodle was detected on the remote host\nunder the path '", dir, "'.");
    }
    else {
      info = string("Moodle ", ver, " was detected on the remote host under the path\n'", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of Moodle were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}
