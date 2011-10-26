#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


  desc["english"] = "
Synopsis :

The remote web server contains a webmail application. 

Description :

The remote host is running SquirrelMail, a PHP-based webmail package
that provides access to mail accounts via POP3 or IMAP. 

See also :

http://www.squirrelmail.org/

Risk factor : 

None";


if (description) {
  script_id(12647);
  script_version("$Revision: 1.10 $");
 
  name["english"] = "SquirrelMail Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the presence of SquirrelMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
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


# Search for SquirrelMail.
if (thorough_tests) dirs = make_list("/squirrelmail", "/webmail", "/mail", "/sm", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:string(dir, "/src/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);
  if (!egrep(pattern:"<title>Squirrel[mM]ail - Login</title>", string:res)) continue;

  # Search in a couple of different pages.
  files = make_list(
    "/src/login.php", "/src/compose.php", "/ChangeLog", "/ReleaseNotes"
  );
  foreach file (files) {
    if (file != "/src/login.php") {
      # Get the page.
      req = http_get(item:string(dir, file), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if (res == NULL) exit(0);
    }

    # Specify pattern used to identify version string.
    if (file == "/src/login.php" || file == "/src/compose.php") {
      pat = "<SMALL>SquirrelMail version (.+)<BR";
    }
    else if (file == "/ChangeLog") {
      pat = "^Version (.+) - [0-9]";
    }
    # nb: this first appeared in 1.2.0 and isn't always accurate.
    else if (file == "/ReleaseNotes") {
      pat = "Release Notes: SquirrelMail (.+) *\*";
    }
    # - someone updated files but forgot to add a pattern???
    else {
      #if (log_verbosity > 1) debug_print("don't know how to handle file '", file, "'!", level:0);
      exit(1);
    }

    # Get the version string.
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match, icase:TRUE);
      if (ver == NULL) break;
      ver = ver[1];

      # Success!
      set_kb_item(
        name:string("www/", port, "/squirrelmail"),
        value:string(ver, " under ", dir)
      );
      installations[dir] = ver;
      ++installs;

      # nb: only worried about the first match.
      break;
    }
    # nb: if we found an installation, stop iterating through files.
    if (installs) break;
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs && !thorough_tests) break;
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("SquirrelMail ", ver, " was detected on the remote host under the\npath '", dir, "'.");
  }
  else {
    info = string(
      "Multiple instances of SquirrelMail were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under '", dir, "'\n");
    }
    info = chomp(info);
  }

  desc["english"] += '\n\nPlugin output :\n\n' + info;
  security_note(port:port, data:desc["english"]);
}
