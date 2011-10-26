#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis : 

The remote web server is running a messaging forum written in PHP. 

Description :

This script detects whether the remote host is running Burning Board
or Burning Board Lite and extracts version numbers and locations of
any instances found. 

WoltLab's Burning Board and Burning Board Lite are message forum
software packages that use PHP and MySQL. 

See also :

http://www.woltlab.com/

Risk factor : 

None";


if (description) {
  script_id(18250);
  script_version("$Revision: 1.3 $");

  name["english"] = "Burning Board Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of Burning Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for Burning Board.
if (thorough_tests) dirs = make_list("/wbboard", "/board", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Grab the Admin Control Panel, which exists in BBLite and BB 2.x;
  # BB 1.x has "/admin/main.php", which doesn't offer a banner.
  req = http_get(item:string(dir, "/acp/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Try to identify the product / version from the banner.
  pat = '<p align="center">WoltLab (Burning Board|Burning Board Lite) ([0-9].+) - Admin Control Panel</p>';
  matches = egrep(string:res, pattern:pat);
  foreach match (split(matches)) {
    match = chomp(match);
    info = eregmatch(pattern:pat, string:match);
    if (!isnull(info)) {
      prod = info[1];
      ver = info[2];
      break;
    }
  }

  # If unsuccessful, try the main page itself.
  if (isnull(ver)) {
    # Grab index.php.
    res = http_get_cache(item:string(dir, "/index.php"), port:port);
    if (res == NULL) exit(0);

    # Try to identify the version from the banner.
    pat = "(Forensoftware|Powered by).+>(Burning Board|Burning Board Lite) ([0-9].+)</[ab]>";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      info = eregmatch(pattern:pat, string:match);
      if (!isnull(info)) {
        prod = info[2];
        ver = info[3];
        break;
      }
    }

    # If unsuccessful, it may be an older version of Burning Board with a multi-line banner.
    if (isnull(ver)) {
      pat = '^ +Board (.+) </b> .+<a href="http://www.woltlab.de" target="_blank">WoltLab';
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          prod = "Burning Board";
          ver = ver[1];
          break;
        }
      }
    }

    # At least try to identify the product (eg, maybe it just doesn't 
    # have a copyright notice).
    if (isnull(prod)) {
      if (
        egrep(string:res, pattern:'<a href="board.php?boardid=[0-9]+(&|&amp;)sid=[^"]">', icase:TRUE) &&
        egrep(string:res, pattern:'<input type="password" name="(l_password|kennwort)"', icase:TRUE)
      ) {
        # Burning Board Lite doesn't have a calendar.
        if ('^ +<a href="calendar.php">') prod = "Burning Board";
        else prod = "Burning Board Lite";
      }

      # Try to grab version from 'acp/lib/inserts.sql'.
      #
      # nb: this may be outdated so use it as a last resort.
      req = http_get(item:dir + "/acp/lib/inserts.sql", port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);
      # Examples:
      #   INSERT INTO bb1_options VALUES (128,0,'boardversion','1.0.2','','','',0);
      #   INSERT INTO bb1_options VALUES (128,0,'boardversion','2.0.2','','','',0);
      pat = "^INSERT INTO bb1_options .+'boardversion','([^']+)',";
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }

      # If we still don't have a version, just mark it as "unknown".
      if (isnull(ver)) ver = "unknown";
    }
  }

  # If we identified the product...
  if (prod) {
    if (dir == "") dir = "/";

    prods[dir] = prod;
    prod = tolower(prod);
    prod = str_replace(string:prod, find:" ", replace:"_");

    set_kb_item(
      name:string("www/", port, "/", prod),
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
      info = string(
        "An unknown version of ", prods[dir], " was detected on the\n",
        "remote host under the path '", dir, "'."
      );
    }
    else {
      info = string(
        prods[dir], " ", ver, " was detected on the remote host under\n",
        "the path '", dir, "'."
      );
    }
  }
  else {
    info = string(
      "Multiple instances of Burning Board were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", prods[dir], " ", installations[dir], ", installed under '", dir, "'\n");
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
