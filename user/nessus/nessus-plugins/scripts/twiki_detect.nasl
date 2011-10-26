#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis : 

The remote web server contains a Wiki system written in Perl. 

Description :

This script detects whether the remote host is running TWiki and
extracts version numbers and locations of any instances found. 

TWiki is an open-source wiki system written in Perl. 

See also : 

http://twiki.org/

Risk factor : 

None";


if (description) {
  script_id(19941);
  script_version("$Revision: 1.5 $");

  name["english"] = "TWiki Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of TWiki";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Search through various directories.
if (thorough_tests) dirs = make_list("/twiki/bin", "/wiki/bin", "/cgi-bin/twiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Try to get the TWiki Web home page.
  req = http_get(item:string(dir, "/view/TWiki/WebHome"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like TWiki...
  if (
    '<div class="twikiMain"><div class="twikiToolBar"><div>' >< res ||
    '/view/TWiki/WebHome?skin=print.pattern">' >< res ||
    'class="twikiFirstCol">' >< res
  ) {
    # Try to pull out the version number.
    pat = "<li> This site is running TWiki version <strong>([^<]+)</strong>";
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

    # If that didn't work, look in TWikiHistory.html.
    if (isnull(ver)) {
      req = http_get(item:string(dir, "/view/TWiki/TWikiHistory"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = '<li> <a href="#.*Release[^"]*">([^<]+)<';
      matches = egrep(pattern:pat, string:res);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = str_replace(string:ver[1], find:"-", replace:" ");

            # releases are listed reverse chronologically; we want only the first.
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/twiki"),
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
      info = string("An unknown version of TWiki was detected on the remote host under\nthe path ", dir, ".");
    }
    else {
      info = string("TWiki ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of TWiki were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc = string(
	desc["english"],
	"\n\nPlugin output :\n\n",
 	info);

  security_note(port:port, data:desc);
}
