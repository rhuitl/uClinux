#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote web server contains an open-source e-learning application
written in PHP. 

Description :

The remote host is running Claroline, an open-source, web-based,
collaborative learning environment written in PHP. 

See also : 

http://www.claroline.net/

Risk factor :

None";


if (description) {
  script_id(22409);
  script_version("$Revision: 1.1 $");

  script_name(english:"Claroline Detection");
  script_summary(english:"Checks for presence of Claroline");
 
  script_description(english:desc);
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/claroline", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like Claroline...
  if (
    '<link href="http://www.claroline.net" rel="Copyright" />' >< res ||
    ' class="claroRightMenu"' >< res ||
    ' class="claroToolTitle"' >< res
  ) {
    # Try to get the version number from the README.txt.
    req = http_get(item:string(dir, "/README.txt"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    pat = "^ +CLAROLINE +(.+) +- +README";
    matches = egrep(pattern:pat, string:res);
    if (matches) {
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
      name:string("www/", port, "/claroline"),
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
      info = string("An unknown version of Claroline was detected on the remote host\nunder the path '", dir, "'.");
    }
    else {
      info = string("Claroline ", ver, " was detected on the remote host under the path\n'", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of Claroline were detected on the remote host:\n",
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
