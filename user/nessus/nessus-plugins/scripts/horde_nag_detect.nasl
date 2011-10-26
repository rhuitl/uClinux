#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a note manager written in PHP. 

Description :

The remote host is running Nag, an open-source PHP-based multi-user
task list manager from the Horde Project. 

See also :

http://www.horde.org/nag/

Risk factor :

None";


if (description) {
  script_id(18135);
  script_version("$Revision: 1.4 $");

  name["english"] = "Nag Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of Nag";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("horde_detect.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!get_kb_item(string("www/", port, "/horde"))) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Search for Nag.
installs = 0;
foreach dir (cgi_dirs()) {
  # Search for version number in a couple of different pages.
  files = make_list(
    "/horde/services/help/?module=nag&show=about",
    "/docs/CHANGES", "/lib/version.phps"
  );

  foreach file (files) {
    # Get the page.
    req = http_get(item:string(dir, file), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);           # can't connect

    if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
      # Specify pattern used to identify version string.
      #
      # - version 2.x
      if (file == "/horde/services/help/?module=nag&show=about") {
        pat = '>This is Nag +(.+).<';
      }
      # - version 1.x
      else if (file == "/docs/CHANGES") {
        pat = "^ *v(.+) *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps") {
        pat = "NAG_VERSION', '(.+)'";
      }
      # - someone updated files but forgot to add a pattern???
      else {
        if (log_verbosity > 1) debug_print("don't know how to handle file '", file, "'!", level:0);
        exit(1);
      }

      # Get the version string.
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (ver == NULL) break;
        ver = ver[1];

        # Success!
        set_kb_item(
          name:string("www/", port, "/horde_nag"),
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
    if (ver == "unknown") {
      info = string("An unknown version of Nag was detected on the remote host under\nthe path ", dir, ".");
    }
    else {
      info = string("Nag ", ver, " was detected on the remote host under the path\n", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of Nag were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}
