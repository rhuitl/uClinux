#
# (C) Tenable Network Security
#


if (description) {
  script_id(19524);
  script_version ("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2673");
  script_bugtraq_id(14617);

  name["english"] = "Burning Board modcp.php SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote version of Burning Board / Burning Board Lite is prone to
SQL injection attacks due to its failure to sanitize user-supplied
input to the 'x' and 'y' parameters of the 'modcp.php' script before
using it in database queries.  Provided an attacker has moderator
privileges, these flaws may allow him to uncover sensitive information
(such as password hashes), modify existing data, and launch attacks
against the underlying database. 

See also : 

http://www.securityfocus.com/archive/1/408660

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:L/Au:R/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerabilities in Burning Board modcp.php script";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test any installs.
wbb = get_kb_list(string("www/", port, "/burning_board"));
wbblite = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(wbb)) {
  if (isnull(wbblite)) exit(0);
  else installs = make_list(wbblite);
}
else if (isnull(wbblite)) {
  if (isnull(wbb)) exit(0);
  else installs = make_list(wbb);
}
else {
  kb1 = get_kb_list(string("www/", port, "/burning_board"));
  kb2 = get_kb_list(string("www/", port, "/burning_board_lite"));
  if ( isnull(kb1) ) kb1 = make_list();
  else kb1 = make_list(kb1);
  if ( isnull(kb2) ) kb1 = make_list();
  else kb2 = make_list(kb2);
  installs = make_list( kb1, kb2 );
}
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];

    if (ver =~ "^2\.([0-2]|3\.[0-3])") {
      security_note(port);
      exit(0);
    }
  }
}
