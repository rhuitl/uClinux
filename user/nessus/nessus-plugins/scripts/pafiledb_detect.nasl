#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote web server contains a download management script written in
PHP. 

Description :

The remote host is running paFileDB, a web-based download management
script written in PHP. 

See also : 

http://www.phparena.net/pafiledb.php

Risk factor :

None";


if (description) {
  script_id(17327);
  script_version("$Revision: 1.3 $");

  script_name(english:"paFileDB Detection");
  script_summary(english:"Checks for presence of paFileDB");

  script_description(english:desc);
 
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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/pafiledb", "/dl", "/downloads", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  req = http_get(item:string(dir, "/pafiledb.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's paFileDB.
  if ("powered by paFileDB" >< res) {
    if (dir == "") dir = "/";

    # Identify the version number.
    pat = "powered by paFileDB (.+)(\. Visit|<br>)";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/pafiledb"),
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
      info = string("An unknown version of paFileDB was detected on the remote\nhost under the path '", dir, "'.");
    }
    else {
      info = string("paFileDB ", ver, " was detected on the remote host under\nthe path '", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of paFileDB were detected on the remote host:\n",
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
