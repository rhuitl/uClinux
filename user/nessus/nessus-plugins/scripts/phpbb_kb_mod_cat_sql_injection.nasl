#
# (C) Tenable Network Security
#


if (description) {
  script_id(18084);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-1196");
  script_bugtraq_id(13219);

  name["english"] = "phpBB Knowledge Base Module SQL Injection Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server contains a PHP application affected by a cross-
site scripting issue. 

Description :

The installed version of phpBB on the remote host includes the
Knowledge Base module, which does not properly sanitize input to the
'cat' parameter of the 'kb.php' script before using it in SQL queries. 
An attacker can exploit this flaw to modify database queries,
potentially even uncovering user passwords for the application. 

See also : 

http://www.securityfocus.com/archive/1/396098

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerability in phpBB Knowledge Base module";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("phpbb_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try a simple exploit.
  req = http_get(item:string(dir, "/kb.php?mode=cat&cat='", SCRIPT_NAME), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error.
  if (egrep(string:res, pattern:string("SQL Error : .+", SCRIPT_NAME, "' at line"), icase:TRUE))
    security_warning(port);
}
