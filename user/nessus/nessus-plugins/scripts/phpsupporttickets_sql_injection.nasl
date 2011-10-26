#
# (C) Tenable Network Security
#


if (description) {
  script_id(20378);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4264");
  script_bugtraq_id(15853);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21730");
  }

  script_name(english:"PHP Support Tickets SQL Injection Vulnerability");
  script_summary(english:"Checks for SQL injection vulnerability in PHP Support Tickets");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by a SQL
injection flaw. 

Description :

The remote host is running PHP Support Tickets, an open-source support
ticketing system written in PHP. 

The installed version of PHP Support Tickets does not validate input
to the 'username' or 'password' parameters of the 'index.php' script
before using it in a database query.  An attacker may be able to
leverage this issue to manipulate SQL queries to, for example, bypass
authentication and gain administrative access to the affected
application. 

See also :

http://www.nii.co.in/vuln/PHPSupportTickets.html

Solution : 

Contact the vendor as reportedly there is a patch to fix the issue. 

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
if (thorough_tests) dirs = make_list("/phpsupporttickets", "/helpdesk", "/support", "/tickets", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check the main index.php page.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like PHP Support Tickets' login form...
  if (
    '<input type="hidden" name="login"' >< res &&
    'Username <input name="username"' >< res &&
    ">PHP Support Tickets v" >< res
  ) {
    # Try to exploit the flaw to get a syntax error.
    postdata = string(
      "login=login&",
      "page=login&",
      "username='", SCRIPT_NAME, "&",
      "password=nessus&",
      "form=Log+In"
    );
    req = string(
      "POST ", dir, "/index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we get a syntax error involving our script name.
    if (
      "an error in your SQL syntax" >< res &&
      string("departments.ID AND username = ''", SCRIPT_NAME) >< res
    ) {
      security_warning(port);
      exit(0);
    }
  }
}

