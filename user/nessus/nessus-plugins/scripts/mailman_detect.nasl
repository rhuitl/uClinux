#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# GPLv2
#
 
  desc = "
Synopsis :

The remote web server contains a mailing list management application
written in Python. 

Description :

The remote host is running Mailman, an open-source, Python-based
mailing list management package. 

See also :

http://www.list.org/

Risk factor : 

None";


if (description) {
  script_id(16338);
  script_version("$Revision: 1.3 $");

  script_name(english:"Mailman Detection");
  script_summary(english:"Checks for the presence of Mailman");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 George A. Theall");

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


# Loop through directories.
if (thorough_tests) dirs = make_list("/mailman", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Search for Mailman's listinfo page.
  listinfo = string(dir, "/listinfo");
  if (dir == "") dir = "/";

  # Get the page.
  req = http_get(item:listinfo, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);           # can't connect

  # Find the version number. It will be in a line such as
  #   <td><img src="/icons/mailman.jpg" alt="Delivered by Mailman" border=0><br>version 2.1.5</td>
  pat = "alt=.Delivered by Mailman..+>version ([^<]+)";
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (ver == NULL) break;
      ver = ver[1];

      # Success!
      set_kb_item(
        name:string("www/", port, "/Mailman"), 
        value:string(ver, " under ", dir)
      );
      installations[dir] = ver;
      ++installs;

      # nb: only worried about the first match.
      break;
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
    info = string("Mailman ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Mailman were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}
