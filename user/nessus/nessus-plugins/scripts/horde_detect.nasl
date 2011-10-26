#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


# NB: I define the script description here so I can later modify
#     it with the version number and install directory.
  desc["english"] = "
This script detects whether the remote host is running Horde and
extracts version numbers and locations of any instances found. 

Horde is a PHP-based application framework from The Horde Project. 
See  http://www.horde.org/horde/  for more information.";


if (description) {
  script_id(15604);
  script_version("$Revision: 1.5 $");
 
  name["english"] = "Horde Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the presence of Horde";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "General";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

if (debug_level) display("debug: looking for Horde on ", host, ":", port, ".\n");

# Search for Horde in a couple of different locations in addition to cgi_dirs().
dirs = make_list(cgi_dirs(), "/horde");

installs = 0;
foreach dir (dirs) {
  # Search for version number in a couple of different pages.
  files = make_list(
    "/services/help/?module=horde&show=about",
    "/docs/CHANGES", "/test.php", "/lib/version.phps",
    "/status.php3"
  );
  foreach file (files) {
    if (debug_level) display("debug: checking ", dir, file, "...\n");

    # Get the page.
    req = http_get(item:string(dir, file), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:"^HTTP/.\.. 200 ")) {
      # Specify pattern used to identify version string.
      # - version 3.x
      if (file =~ "^/services/help") {
        pat = ">This is Horde (.+)\.<";
      }
      # - version 2.x
      else if (file == "/docs/CHANGES") {
        pat = "^ *v(.+) *$";
      }
      #   nb: test.php available is itself a vulnerability but sometimes available.
      else if (file == "/test.php") {
        pat = "^ *<li>Horde: +(.+) *</li> *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps") {
        pat = "HORDE_VERSION', '(.+)'";
      }
      # - version 1.x
      else if (file == "/status.php3") {
        pat = ">Horde, Version (.+)<";
      }
      # - someone updated files but forgot to add a pattern???
      else {
        if (debug_level) display("Don't know how to handle file '", file, "'!\n");
        exit(1);
      }

      # Get the version string.
      if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
        ver = eregmatch(pattern:pat, string:match);
        if (ver == NULL) break;
        ver = ver[1];
        if (debug_level) display("debug: Horde version =>>", ver, "<<\n");

        # Success!
        set_kb_item(
          name:string("www/", port, "/horde"), 
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
    info = string("Horde ", ver, " was detected on the target under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Horde were detected on the target:\n",
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
