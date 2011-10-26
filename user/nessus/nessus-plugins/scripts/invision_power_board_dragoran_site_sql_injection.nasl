#
# (C) Tenable Network Security
#


if (description) {
  script_id(20835);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0520");
  script_bugtraq_id(16447);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"22851");
  }

  script_name(english:"Invision Power Board Dragoran Portal Plugin site Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for site parameter SQL injection vulnerability in Invision Power Board Dragoran Portal Plugin");
 
  desc = "
Synopsis : 

The remote web server contains a PHP application that is affected by
SQL injection attacks. 

Description :

The installation of Invision Power Board on the remote host contains
an optional plugin module known as Dragoran Portal that fails to
sanitize input to the 'site' parameter of the 'index.php' script
before using it in database queries.  An attacker may be able to
leverage this issue to disclose sensitive information, modify data, or
launch attacks against the underlying database. 

Solution :

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  magic = string(rand() % 100, " UNION SELECT ", rand() % 100);
  req = http_get(
    item:string(
      dir, "/index.php?",
      "act=portal&",
      "site=", urlencode(str:magic)
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error.
  if (egrep(pattern:string("mySQL query error: SELECT .+portal_sites +WHERE id=", magic), string:res)) {
    security_warning(port);
    exit(0);
  }
}
