#
# (C) Tenable Network Security
#


if (description) {
  script_id(18005);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1051");
  script_bugtraq_id(13071);

  name["english"] = "PunBB profile.php SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection flaw. 

Description :

According to its banner, the version of PunBB installed on the remote
host fails to properly sanitize user input to the script 'profile.php'
through the 'change_email' parameter prior to using it in a SQL query. 
Once authenticated, an attacker can exploit this flaw to manipulate
database queries, even gaining administrative access. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=111306207306155&w=2

Solution : 

Upgrade to PunBB version 1.2.5 or newer.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerability in PunBB's profile.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
#
# nb: we can't exploit this without logging in as a user.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.(1|2$|2\.[1-4]([^0-9]|$))") security_note(port);
}
