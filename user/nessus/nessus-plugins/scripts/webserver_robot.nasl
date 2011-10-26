#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a 'robots.txt' file.

Description :

The remote host contains a file named 'robots.txt' that is intended to
prevent web 'robots' from visiting certain directories in a web site for
maintenance or indexing purposes.  A malicious user may also be able to
use the contents of this file to learn of sensitive documents or
directories on the affected site and either retrieve them directly or
target them for other attacks. 

See also : 

http://www.robotstxt.org/wc/exclusion.html

Solution : 

Review the contents of the site's robots.txt file, use Robots META tags
instead of entries in the robots.txt file, and/or adjust the web
server's access controls to limit access to sensitive material. 

Risk factor :

None";


if (description) {
  script_id(10302);
  script_version("$Revision: 1.28 $");

  name["english"] = "Robots.txt Information Disclosure";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for a web server's robots.txt";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Try to retrieve the file.
req = http_get(item:"/robots.txt", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# nb: <http://www.robotstxt.org/wc/norobots-rfc.html> describes
#     how the file should look.
if (egrep(string:res, pattern:"^[ \t]*((A|Disa)llow|User-Agent):", icase:TRUE)) {
  if (report_verbosity > 0) {
    desc["english"] += '\n\nContents of robots.txt :\n\n' + res;
  }
  security_note(port:port, data:desc["english"]);
  exit(0);
}
