#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
Synopsis :

The remote web server contains a blog script written in PHP.

Description :

This script detects whether the remote host is running WordPress and
extracts version numbers and locations of any instances found. 

WordPress is a free blog software written in PHP and with a MySQL
back-end. 

See also : 

http://www.wordpress.org/

Risk factor : 

None";


if (description) {
  script_id(18297);
  script_version("$Revision: 1.8 $");

  name["english"] = "WordPress Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of WordPress";
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


# Search for WordPress.
installs = 0;
foreach dir (cgi_dirs()) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  if ( strlen(res) > 512 ) subres = substr(res, 0, 512 );
  else subres = res;

  # Try to identify the version number from the Generator meta tag.
  pat = '<meta name="generator" content="WordPress (.+)" />';
  matches = egrep(pattern:pat, string:subres);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }

    # If that didn't work, look in readme.html.
    if (isnull(ver)) {
      req = http_get(item:string(dir, "/readme.html"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = "^ +Version ([^<]+)</h1>";
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
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/wordpress"),
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
      info = string("An unknown version of WordPress was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("WordPress ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of WordPress were detected on the remote host:\n",
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
