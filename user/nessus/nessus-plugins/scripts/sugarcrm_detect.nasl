#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a CRM system written in PHP. 

Description :

This script detects whether the remote host is running Sugar Open Source
and extracts version numbers and locations of any instances found. 

Sugar Open Source is a customer relationship management (CRM)
application written in PHP. 

See also : 

http://www.sugarforge.org/

Risk: 

None";


if (description) {
  script_id(19496);
  script_version("$Revision: 1.5 $");

  name["english"] = "Sugar Open Source Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for presence of Sugar Open Source";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for Sugar Open Source.
if (thorough_tests) dirs = make_list("/sugarcrm", "/sugar", "/SugarCRM", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like Sugar Open Source...
  if (
    "<!--SugarCRM - Commercial Open Source CRM-->" >< res ||
    "alt='Powered By SugarCRM'>" >< res
  ) {
    # Try to grab the version number from README.txt - Sugar only 
    # displays it normally to logged-in users.
    req = http_get(item:string(dir, "/README.txt"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    pat = "^Sugar Suite v([0-9].+)$";
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

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/sugarcrm"),
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
      info = string("An unknown version of Sugar Open Source was detected on the\nremote host under the path ", dir, ".");
    }
    else {
      info = string("Sugar Open Source ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of Sugar Open Source were detected on the remote host:\n",
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
