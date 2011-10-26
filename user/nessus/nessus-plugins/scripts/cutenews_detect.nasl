#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a news management script written in PHP.

Description :

The remote host is running CuteNews, a news management script written in 
PHP that uses flat files for storage.  

See also : 

http://cutephp.com/cutenews/

Risk factor :

None";


if (description) {
  script_id(17255);
  script_version("$Revision: 1.6 $");

  name["english"] = "CuteNews Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of CuteNews";
  script_summary(english:summary["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for CuteNews.
if (thorough_tests) dirs = make_list("/cutenews", "/news", "/cute", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it's CuteNews.
  if (res =~ "Powered by .+CuteNews") {
    if (dir == "") dir = "/";

    # Try to identify the version number from index.php.
    pat = "Powered by .+>CuteNews (.+)</a>";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
    # If unsuccessful, try to grab it from the README.
    if (isnull(ver)) {
      req = http_get(item:dir + "/README.htm", port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);

      pat = '<p align="left">CuteNews v(.+) by <a';
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

    set_kb_item(
      name:string("www/", port, "/cutenews"),
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
      info = string("An unknown version of CuteNews was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("CuteNews ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of CuteNews were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc["english"] += '\n\nPlugin output :\n\n' + info;
  security_note(port:port, data:desc["english"]);
}
