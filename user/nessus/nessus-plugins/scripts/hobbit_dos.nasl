#
# (C) Tenable Network Security
#


if (description) {
  script_id(19307);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(14365);

  name["english"] = "Hobbit Monitor Remote Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server may allow arbitrary code execution.

Description :

The remote host is running Hobbit Monitor, an open-source tool for
monitoring servers, applications, and networks. 

The installed version of Hobbit contains a flaw that could lead to the
Hobbit daemon, 'hobbitd', crashing when it tries to process certain
types of messages.  It may also be possible to exploit this flaw in
order to run arbitrary code with the privileges of the hobbit user. 

See also :

http://www.hswn.dk/hobbiton/2005/07/msg00242.html
http://sourceforge.net/project/shownotes.php?release_id=344499

Solution : 

Upgrade to Hobbit version 4.1.0 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for denial of service vulnerability in Hobbit Monitor";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # There's a problem if ...
  if (
    # it looks like Hobbit Monitor and ...
    egrep(string:res, pattern:"<TITLE>.+ : Hobbit - Status @ ") &&
    # the banner indicates it's a version between 4.0 and 4.0.4 inclusive.
    egrep(string:res, pattern:">Hobbit Monitor 4\.0([^.]|\.[0-4]</A>)")
  ) {
    security_hole(port);
    exit(0);
  }
}
