#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a content management system (CMS)
written in PHP. 

Description :

This script detects whether the remote host is running e107 and
extracts version numbers and locations of any instances found. 

e107 is a content management system written in PHP and with a MySQL
back-end. 

See also : 

http://e107.org/news.php

Risk factor : 

None";


if (description) {
  script_id(20129);
  script_version("$Revision: 1.2 $");

  script_name(english:"e107 Detection");
  script_summary(english:"Checks for the presence of e107");
 
  script_description(english:desc);
 
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


# Search for e107.
if (thorough_tests) dirs = make_list("/e107", "/cms", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Try to grab e107's main admin page.
  req = http_get(item:string(dir, "/e107_admin/admin.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like the right page...
  if (egrep(pattern:"<input [^>]*name='auth(name|pass)'", string:res)) {

    # It doesn't seem possible to identify the version so just 
    # mark it as "unknown".
    #if (isnull(ver)) ver = "unknown";
    ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/e107"),
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
      info = string("An unknown version of e107 was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("e107 ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of e107 were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  report = ereg_replace(
    string:desc,
    pattern:"This script[^\.]+\.", 
    replace:info
  );
  security_note(port:port, data:report);
}
