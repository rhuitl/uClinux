#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote web server contains a bulletin board system written in PHP. 

Description :

The remote host is running MyBB (formerly known as MyBulletinBoard), a
web-based bulletin board system written in PHP and using MySQL for its
back-end storage. 

See also : 

http://mybboard.com/

Risk factor :

None";


if (description) {
  script_id(20841);
  script_version("$Revision: 1.2 $");

  script_name(english:"MyBB Detection");
  script_summary(english:"Checks for presence of MyBB");
 
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
if (thorough_tests) dirs = make_list("/mybb", "/forum", "/forums", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it's MyBB.
  if (egrep(pattern:"Powered [bB]y <[^>]+>My(BB|BulletinBoard)</", string:res)) {
    if (dir == "") dir = "/";

    # Try to identify the version number from index.php.
    #
    # nb: don't put much trust in this -- the vendor habitually
    #     releases patches that do not update the version number.
    pat = "Powered [bB]y <[^>]+>My(BB|BulletinBoard)</a> ([^<]+)<br />";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[2];
        break;
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/mybb"),
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
      info = string("An unknown version of MyBB was detected on the remote\nhost under the path '", dir, "'.");
    }
    else {
      info = string("MyBB ", ver, " was detected on the remote host under\nthe path '", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of MyBB were detected on the remote host:\n",
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
