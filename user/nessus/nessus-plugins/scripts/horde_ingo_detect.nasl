#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a web-based email filter management
application. 

Description :

The remote host is running Horde, a PHP-based application from the
Horde Project for managing email filter rules. 

See also :

http://www.horde.org/ingo/

Risk factor :

None";


if (description)
{
  script_id(22899);
  script_version("$Revision: 1.1 $");

  script_name(english:"Ingo Detection");
  script_summary(english:"Checks for presence of Ingo");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("horde_detect.nasl");
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


# Search for Ingo.
installs = 0;

install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Get the help page.
  req = http_get(
    item:string(
      dir, "/services/help/?",
      "module=ingo&",
      "show=about"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  ver = NULL;
  pat = '>This is Ingo +(.+)\\.<';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }

  if (!isnull(ver))
  {
    if (dir == "/") dir = "/ingo";
    else dir += "/ingo";

    set_kb_item(
      name:string("www/", port, "/horde_ingo"),
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (ver == "unknown") {
    info = string("An unknown version of Ingo was detected on the remote host under\nthe path '", dir, "'.");
  }
  else {
    info = string("Ingo ", ver, " was detected on the remote host under the \npath '", dir, "'.");
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
