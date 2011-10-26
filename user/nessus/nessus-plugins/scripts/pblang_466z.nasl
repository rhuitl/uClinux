#
# (C) Tenable Network Security
#


if (description) {
  script_id(19593);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(14728);

  name["english"] = "PBLang < 4.66z Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains various PHP scripts that are prone to
information disclosure, message deletion, and privilege escalation. 

Description :

The remote host is running PBLang, a bulletin board system that uses
flat files and is written in PHP. 

According to its banner, the version of PBLang installed on the remote
host allows an attacker to inject code and create a user with
administrative privileges, certain users to access restricted forums
without proper permissions, and authenticated users to delete other
users' private messages. 

See also : 

http://sourceforge.net/project/shownotes.php?release_id=353425

Solution : 

Upgrade to PBLang 4.66z or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PBLang < 4.66z";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Get the initial page.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Check the version number.
  if (
    egrep(string:res, pattern:'<A HREF="http://pblang\\.drmartinus\\.de/[^>]+>Software PBLang ([0-3]\\.|4\\.([0-5].*|6([0-5].*|6[a-y]?)))<') ||
    egrep(string:res, pattern:'<meta name="description" content=".+running with PBLang ([0-3]\\.|4\\.([0-5].*|6([0-5].*|6[a-y]?)))">')
  ) {
    security_note(port);
    exit(0);
  }
}
