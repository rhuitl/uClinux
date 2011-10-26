#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a bulletin-board system written in PHP. 

Description :

This script detects whether the remote host is running UBB.threads and
extracts version numbers and locations of any instances found. 

UBB.threads is a web-based message board software system written in
PHP. 

See also : 

http://www.ubbcentral.com/

Risk factor : 

None";


if (description) {
  script_id(17315);
  script_version("$Revision: 1.5 $");

  name["english"] = "UBB.threads Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of UBB.threads";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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


# Loop through directories.
if (thorough_tests) dirs = make_list("/ubbthreads", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  req = http_get(item:string(dir, "/ubbthreads.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's UBB.threads.
  if (
    '<a href="http://www.infopop.com/landing/goto.php?a=ubb.threads' >< res ||
    '<A HREF="http://www.ubbthreads.com' >< res
  ) {
    if (dir == "") dir = "/";

    # Try to identify the version number from main page.
    #
    # nb: there have been a couple of different styles used.
    pat = "(^UBB\.threads&trade;|>Powered By UBB\.threads&trade;|>Powered BY UBBThreads) ([^<]+)";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[2];
        break;
      }
    }
    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    set_kb_item(
      name:string("www/", port, "/ubbthreads"),
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
      info = string("An unknown version of UBB.threads was detected on the remote\nhost under the path '", dir, "'.");
    }
    else {
      info = string("UBB.threads ", ver, " was detected on the remote host under\nthe path '", dir, "'.");
    }
  }
  else {
    info = string(
      "Multiple instances of UBB.threads were detected on the remote host:\n",
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
