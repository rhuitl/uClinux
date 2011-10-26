#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a mailing list manager written in PHP. 

Description :

This script detects whether the remote host is running PHPlist and
extracts version numbers and locations of any instances found. 

PHPlist is a free, web-based mailing list manager that uses PHP and
MySQL. 

See also :

http://tincan.co.uk/phplist

Risk factor : 

None";


if (description) {
  script_id(19313);
  script_version("$Revision: 1.3 $");

  script_name(english:"PHPlist Detection");
  script_summary(english:"Checks for presence of PHPlist");
 
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
if (!can_host_php(port:port)) exit(0);


# Search for PHPlist.
if (thorough_tests) dirs = make_list("/phplist", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Get page for subscribing to a mailing list.
  req = http_get(item:string(dir, "/lists/?p=subscribe"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If the page looks like it's from PHPlist...
  if ('<link rev="made" href="mailto:phplist%40tincan.co.uk"' >< res) {

    # Sometimes the version number can be found in a META tag.
    pat = 'meta name="Powered-By" content="PHPlist version (.+)"';
    matches = egrep(string:res, pattern:pat);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
    # Otherwise, try in the "Powered by" line.
    if (isnull(ver)) {
      pat = "owered by (PHPlist version |.+>phplist</a> v )(.+), &copy;";
      matches = egrep(string:res, pattern:pat);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(string:match, pattern:pat);
        if (!isnull(ver)) {
          ver = ver[2];
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/phplist"),
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
      info = string("An unknown version of PHPlist was detected on the remote host under the path\n'", dir, "'.");
    }
    else {
      info = string("PHPlist ", ver, " was detected on the remote host under the path\n'", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of PHPlist were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under '", dir, "'.\n");
    }
    info = chomp(info);
  }

  desc += '\n\nPlugin output :\n\n' + info;
  security_note(port:port, data:desc);
}
