#
# (C) Tenable Network Security
#


if (description) {
  script_id(20254);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3996");
  script_bugtraq_id(15690);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21411");
  }

  script_name(english:"Zen Cart admin_email Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for admin_email parameter SQL injection vulnerability in Zen Cart");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by a SQL
injection flaw. 

Description :

The remote host is running Zen Cart, an open-source web-based shopping
cart written in PHP. 

The installed version of Zen Cart does not validate input to the
'admin_email' parameter of the 'admin/password_forgotten.php' script
before using it in a database query.  Regardless of PHP's
'magic_quotes_gpc' setting, an attacker can leverage this issue to
manipulate SQL queries, possibly gaining the ability to execute
arbitrary PHP code on the remote host subject to the privileges of the
web server user id. 

See also :

http://retrogod.altervista.org/zencart_126d_xpl.html

Solution :

Configure the database so it can not write to files in the web
server's document directory. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
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
if (thorough_tests) dirs = make_list("/cart", "/catalog", "/store", "/shop", "/zencart", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  url = string(dir, "/admin/password_forgotten.php");

  # Make sure the affected script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ('name="admin_email" value="" />' >< res) {
    # Try to exploit the flaw to get a syntax error.
    postdata = string(
      "admin_email='", SCRIPT_NAME, "&",
      "submit=resend"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we get a syntax error involving our script name.
    if (egrep(pattern:string("an error in your SQL syntax.+ near '", SCRIPT_NAME), string:res)) {
      security_warning(port);
      exit(0);
    }
  }
}
