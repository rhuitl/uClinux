#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a content management system written in
PHP. 

Description :

This script detects whether the remote host is running Xoops and
extracts version numbers and locations of any instances found. 

Xoops is a web content management system written in PHP and released
under the GPL.

See also : 

http://www.xoops.org/

Risk factor : 

None";


if (description) {
  script_id(18613);
  script_version("$Revision: 1.3 $");

  name["english"] = "Xoops Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects Xoops";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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


# Search for Xoops.
if (thorough_tests) dirs = make_list("/xoops", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Grab lostpass.php.
  req = http_get(item:string(dir, "/lostpass.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like Xoops...
  if ('<meta http-equiv="Refresh" content="2; url=user.php?xoops_redirect=' >< res) {
    # Try to identify the version number.

    # nb: at least through 2.0.12, the version number is embedded in the
    #     Generator meta tag in the printer-friendly version of a story id.
    #     Since the news module is optional, though, this approach won't 
    #     always work.
    req = http_get(item:string(dir, "/modules/news/index.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    pat = "/modules/news/article\.php\?storyid=([0-9]+)";
    if (egrep(string:res, pattern:pat)) {
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        id = eregmatch(pattern:pat, string:match);
        if (!isnull(id)) {
          id = id[1];

          # Try to request a printer-friendly formatted version.
          req = http_get(item:string(dir, "/modules/news/print.php?storyid=", id), port:port);
          res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
          if (res == NULL) exit(0);

          pat = '<meta name="GENERATOR" content="XOOPS ([^"]+)"';
          if (egrep(string:res, pattern:pat)) {
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

          # nb: we only need one story id.
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/xoops"),
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
      info = string("An unknown version of Xoops was detected on the remote host under the\npath '", dir, "'.");
    }
    else {
      info = string("Xoops ", ver, " was detected on the remote host under the path\n'", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of Xoops were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc = ereg_replace(
    string:desc["english"],
    pattern:"This script[^\.]+\.", 
    replace:info
  );
  security_note(port:port, data:desc);
}
