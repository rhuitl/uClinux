#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15936);
  script_version("$Revision: 1.7 $");
  script_name(english:"PunBB detection");

  desc["english"] = "
Synopsis :

The remote web server contains a database management application
written in PHP. 

Description :

This script detects whether the remote host is running PunBB and
extracts the version number and location if found. 

PunBB is an open-source discussion board written in PHP. 

See also :

http://www.punbb.org/
	
Risk factor : 

None";

  script_description(english:desc["english"]);

  script_summary(english:"Checks for presence of PunBB");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Search for punBB.
if (thorough_tests) dirs = make_list("/punbb", "/forum", "/forums", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  r = http_get_cache(item:string(dir, "/index.php"), port:port);
  if ( r == NULL ) exit(0);

  pat = "Powered by .*http://www\.punbb\.org/.>PunBB";
  if ( egrep(pattern:pat, string:r) ) {
    if ( ! dir ) dir = "/";
    version=eregmatch(pattern:string(".*", pat, "</a><br>.+Version: (.+)<br>.*"),string:r);
    # nb: starting with 1.2, version display is optional and off by default
    #     but it's still useful to know that it's installed.
    if ( version == NULL ) {
      version = "unknown";
      report = string("An unknown version of PunBB is installed under ", dir, " on the remote host.");
    }
    else {
      version = version[1];
      report = string("PunBB version ", version, " is installed under ", dir, " on the remote host.");
    }

    desc["english"] += '\n\nPlugin output :\n\n' + report;
    security_note(port:port, data:desc["english"]);

    set_kb_item(name:"www/" + port + "/punBB", value:version + " under " + dir);

    exit(0);
  }
}
