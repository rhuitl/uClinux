#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


if (description) {
  script_id(19765);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2954");
  script_bugtraq_id(14831);
  script_xref(name:"OSVDB", value:"19411");

  name["english"] = "ATutor password reminder SQL injection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains a PHP script vulnerable to a SQL injection
vulnerability. 

Description :

The remote host is running ATutor, an open source web-based Learning
Content Management System (LCMS) designed with accessibility and
adaptability in mind. 

The remote version of this software contains an input validation flaw
in the 'password_reminder.php' script.  This vulnerability occurs only
when 'magic_quotes_gpc' is set to off in the 'php.ini' configuration
file.  A malicious user can exploit this flaw to manipulate SQL
queries and steal any user's password. 

See also : 

http://retrogod.altervista.org/atutor151.html

Solution : 

Upgrade to ATutor 1.5.1 pl1 or later

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection in password_reminder.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"(C) 2005 Josh Zlatin-Amishav");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
      
postdata = string(
  "form_password_reminder=true&",
  "form_email=%27", SCRIPT_NAME, "&",
  "submit=Submit"
);

foreach dir ( cgi_dirs() )
{
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/password_reminder.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    "ATutor" >< res &&
    '<input type="hidden" name="form_password_reminder"' >< res
  ) {
    req = string(
      "POST ", dir, "/password_reminder.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    if ( "mysql_fetch_assoc(): supplied argument is not a valid MySQL result resource" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}
