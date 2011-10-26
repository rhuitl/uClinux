#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22233);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-4214");
  script_bugtraq_id(19542);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"28144");

  script_name(english:"Zen Cart custom SQL Injection Vulnerability");
  script_summary(english:"Checks for SQL injection flaw in Zen Cart");

  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a SQL
injection attack. 

Description :

The remote host is running Zen Cart, an open-source web-based shopping
cart written in PHP. 

The version of Zen Cart installed on the remote host fails to properly
sanitize input to the 'custom' parameter of the 'ipn_main_handler.php'
script before using it in a database query.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
may be able to exploit this issue to uncover sensitive information
such as password hashes, modify data, launch attacks against the
underlying database, etc. 

See also :

http://www.gulftech.org/?node=research&article_id=00109-08152006
http://www.zen-cart.com/forum/showthread.php?t=43579

Solution :

Apply the security patches listed in the vendor advisory above. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "no404.nasl");
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
if (get_kb_item("www/no404/" + port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/cart", "/catalog", "/store", "/shop", "/zencart", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/ipn_main_handler.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it does...
  #
  # nb: the script only responds to POSTs.
  if (egrep(string:res, pattern:"^HTTP/.* 200 OK"))
  {
    # Try to exploit the flaw to generate a syntax error.
    postdata = string(
      "custom=nessus='", SCRIPT_NAME
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
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see an error message with our script name.
    if (string("right syntax to use near '", SCRIPT_NAME, "''") >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
