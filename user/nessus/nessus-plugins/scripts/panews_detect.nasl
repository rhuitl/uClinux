#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a news management application written
in PHP. 

Description :

The remote host is running paNews, a news management application
written in PHP. 

See also : 

http://www.phparena.net/panews.php

Risk factor :

None";


if (description) {
  script_id(17253);
  script_version("$Revision: 1.6 $");

  name["english"] = "paNews Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of paNews";
  script_summary(english:summary["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
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
if (thorough_tests) dirs = make_list("/panews", "/news", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it's paNews.
  if (res =~ "<p align=.*paNews .+www\.phparena\.net.*phpArena") {
    if (dir == "") dir = "/";

    # Identify the version number.
    pat = "<p align=.*paNews (.+) &copy; .*www\.phparena\.net.*phpArena";
    matches = egrep(pattern:pat, string:res);
    ver = NULL;
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
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/panews"), 
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
      info = string("An unknown version of paNews was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("paNews ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of paNews were detected on the remote host:\n",
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
