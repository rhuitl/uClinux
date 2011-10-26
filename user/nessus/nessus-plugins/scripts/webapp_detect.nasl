#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a web portal system written in Perl. 

Description :

This script detects whether the remote host is running WebAPP and
extracts version numbers and locations of any instances found. 

WebAPP is an open-source, web portal system written in Perl. 

See also :

http://www.web-app.org/

Risk factor : 

None";


if (description) {
  script_id(18287);
  script_version("$Revision: 1.4 $");

  script_name(english:"WebAPP Detection");
  script_summary(english:"Checks for presence of WebAPP");
 
  script_description(english:desc);
 
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


# Search for WebAPP.
installs = 0;
foreach dir (cgi_dirs()) {
  # Grab index.cgi.
  req = http_get(item:string(dir, "/index.cgi"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Try to identify the version number from the Generator meta tag.
  pat = '<meta name="Generator" content="WebAPP (.+)">';
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

    # If that didn't work, try the banner.
    if (isnull(ver)) {
      pat = 'class="webapplink">WebAPP v([^<]+)</a>';
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

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/webapp"),
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
      info = string("An unknown version of WebAPP was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("WebAPP ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of WebAPP were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}
