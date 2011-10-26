#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22055);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(18997);

  script_name(english:"MyBB CLIENT-IP SQL Injection Vulnerability");
  script_summary(english:"Checks for CLIENT-IP SQL injection vulnerability in MyBB");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to a SQL injection attack. 

Description :

The remote version of MyBB fails to sanitize input to the 'CLIENT-IP'
request header before using it in a database query when initiating a
sesion in 'inc/class_session.php'.  This may allow an unauthenticated
attacker to uncover sensitive information such as password hashes,
modify data, launch attacks against the underlying database, etc. 

Note that successful exploitation is possible regardless of PHP's
settings. 

See also :

http://retrogod.altervista.org/mybb_115_sql.html
http://www.securityfocus.com/archive/1/440163/30/0/threaded
http://community.mybboard.net/showthread.php?tid=10555

Solution :

Upgrade to MyBB version 1.1.6 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
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
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  magic = string("'", SCRIPT_NAME, "/*");

  req = http_get(item:string(dir, "/"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "CLIENT-IP: ", magic, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error with our script name.
  if (
    "mySQL error: 1064" >< res &&
    string("near ", magic, "'' at line") >< res &&
    "SELECT sid,uid" >< res
  )
  {
    security_hole(port);
    exit(0);
  }
}
