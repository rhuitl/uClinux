#
# (C) Tenable Network Security
#


if (description) {
  script_id(19760);
  script_version ("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3019", "CVE-2005-3020");
  script_bugtraq_id(14872, 14874);

  name["english"] = "vBulletin <= 3.0.9 Multiple Vulnerabilities";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to several
flaws.

Description :

The version of vBulletin installed on the remote host fails to
properly sanitize user-supplied input to a number of parameters and
scripts before using it in database queries and to generate dynamic
HTML.  An attacker can exploit these issues to launch SQL injection
and cross-site scripting attacks against the affected application. 
Note that the affected scripts require moderator or administrator
access, with the exception of 'joinrequests.php'. 

See also : 

http://morph3us.org/advisories/20050917-vbulletin-3.0.8.txt

Solution : 

Upgrade to vBulletin 3.0.9 to resolve many but not all of these issues.

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for multiple vulnerabilities in vBulletin <= 3.0.9";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/www", 80);
  script_dependencies("vbulletin_detect.nasl");

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: 3.0.9 and below are affected.
  if (ver =~ "^([0-2]\.|3\.0\.[0-9]($|[^0-9]))") {
    security_warning(port);
    exit(0);
  }
}
