#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a FAQ-system script written in PHP.

Description :

This script detects whether the remote host is running phpMyFAQ and
extracts version numbers and locations of any instances found. 

phpMyFAQ is a multilingual database-driven FAQ-system using PHP and
MySQL.  

See also : 

http://www.phpmyfaq.de/

Risk factor : 

None";


if (description) {
  script_id(17297);
  script_version("$Revision: 1.5 $");

  name["english"] = "phpMyFAQ Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of phpMyFAQ";
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


# Search for phpMyFAQ.
if (thorough_tests) dirs = make_list("/faq", "/phpmyfaq", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it's phpMyFAQ.
  if (egrep(string:res, pattern:"Powered by .+phpMyFAQ")) {
    if (dir == "") dir = "/";

    # Try to identify the version number from index.php.
    pat = 'powered by .*phpMyFAQ.* ([0-9][^"<&]+)';
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
      req = http_get(item:dir + "/docs/README.txt", port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);

      pat = '^phpMyFAQ (.+)$';
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
      name:string("www/", port, "/phpmyfaq"),
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
      info = string("An unknown version of phpMyFAQ was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("phpMyFAQ ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of phpMyFAQ were detected on the remote host:\n",
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
