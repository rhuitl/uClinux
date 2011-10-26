#
# (C) Tenable Network Security
#


if (description) {
  script_id(17314);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2005-0774",
    "CVE-2005-0775",
    "CVE-2005-0776",
    "CVE-2005-0777",
    "CVE-2005-0778",
    "CVE-2005-1629"
  );
  script_bugtraq_id(12779, 13620);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14679");
    script_xref(name:"OSVDB", value:"14680");
    script_xref(name:"OSVDB", value:"14681");
    script_xref(name:"OSVDB", value:"14682");
    script_xref(name:"OSVDB", value:"14683");
    script_xref(name:"OSVDB", value:"16731");
  }

  name["english"] = "Multiple Remote Vulnerabilities in PhotoPost PHP 5.0 RC3 and Older";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
several vulnerabilities. 

Description :

According to its banner, the version of PhotoPost PHP installed on the
remote host is prone to several remote vulnerabilities:

  - An Access Validation Vulnerability.
    The 'adm-photo.php' script fails to verify authentication
    credentials, which allows an attacker to change the 
    properties of thumbnails of uploaded images.

  - A SQL Injection Vulnerability.
    The 'uid' parameter in the 'member.php' script is not 
    properly sanitized before use in SQL queries. An
    attacker can leverage this flaw to disclose or modify
    sensitive information or perhaps even launch attacks
    against the underlying database implementation.

  - A Cross-site Scripting (XSS) Vulnerability.
    The 'editbio' parameter of the user profile form is not sanitized
    properly, allowing an attacker to inject arbitrary script or
    HTML in a user's browser in the context of the affected web site, 
    resulting in theft of authentication data or other such attacks. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-03/0200.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-05/0298.html

Solution : 

Upgrade to PhotoPost PHP version 5.01 or later.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote vulnerabilities in PhotoPost PHP 5.0 RC3 and older";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("photopost_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^[0-4].*|5\.0[^0-9]?|5\.0rc[123]$") security_warning(port);
}
