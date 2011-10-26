#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a wiki application written in PHP. 

Description :

This script detects whether the remote host is running MediaWiki and
extracts version numbers and locations of any instances found. 

MediaWiki is an open-source wiki application written in PHP.

See also : 

http://wikipedia.sourceforge.net/

Risk factor : 

None";


if (description) {
  script_id(19233);
  script_version("$Revision: 1.3 $");

  name["english"] = "MediaWiki Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects MediaWiki";
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


# Search for MediaWiki.
if (thorough_tests) dirs = make_list("/wiki", "/Wiki", "/mediawiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Request index.php and try to get the version number.
  req = http_get(item:string(dir, "/index.php?title=Special:Version"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like MediaWiki...
  if ('<div id="f-poweredbyico"><a href="http://www.mediawiki.org/">' >< res) {
    # nb: the installation may require authentication, but the
    #     page will at least clue us in to MediaWiki's presence.
    #
    # nb: this doesn't catch the really old versions (MediaWiki-stable 
    #     20031117 and older), but they no longer appear to be deployed.
    pat = ">MediaWiki</a>.+: ([0-9]+\.[0-9]+.*)";
    if (egrep(string:res, pattern:pat)) {
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # If that didn't work, try to get it from the release notes.
    if (isnull(ver)) {
      req = http_get(item:string(dir, "/RELEASE-NOTES"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = "^== MediaWiki ([0-9]+\.[0-9]+.*) ==";
      if (egrep(string:res, pattern:pat)) {
        matches = egrep(pattern:pat, string:res);
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
      name:string("www/", port, "/mediawiki"),
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
      info = string("An unknown version of MediaWiki was detected on the remote host\nunder the path '", dir, "'.");
    }
    else {
      info = string("MediaWiki ", ver, " was detected on the remote host under the path\n'", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of MediaWiki were detected on the remote host:\n",
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
