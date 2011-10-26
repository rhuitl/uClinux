#
# (C) Tenable Network Security
#


if (description) {
  script_id(19715);
  script_version ("$Revision: 1.4 $");

  script_bugtraq_id(14762);

  name["english"] = "MyBB fid Parameter SQL Injection Vulnerability (2)";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote version of MyBB is prone to a SQL injection attack due to
its failure to sanitize user-supplied input to the 'fid' parameter of
the 'misc.php' script before using it in database queries. 

See also :

http://www.securityfocus.com/archive/1/409743/30/0/threaded

Solution : 

Enable PHP's 'magic_quotes_gpc' setting.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for fid parameter SQL injection vulnerability in MyBB (2)";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
  script_dependencies("mybb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaws.
  req = http_get(
    item:string(
      dir, "/misc.php?",
      "action=rules&",
      "fid=-1'", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error with our script name.
  if (
    egrep(
      string:res,
      pattern:string("mySQL error: 1064<br>.+near '", SCRIPT_NAME, "' .+Query: SELECT \\* FROM .*forums")
    )
  ) {
    security_warning(port);
    exit(0);
  }
}
