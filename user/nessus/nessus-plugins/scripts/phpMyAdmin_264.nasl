#
# (C) Tenable Network Security
#


if (description) {
  script_id(19519);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-2869");
  script_bugtraq_id(14674, 14675);

  name["english"] = "PHPMyAdmin < 2.6.4 Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP application that is affected by
cross-site scripting vulnerabilities. 

Description :

According to its banner, the version of phpMyAdmin installed on the
remote host may suffer from two cross-site scripting vulnerabilities
due to its failure to sanitize user input to the 'error' parameter of
the 'error.php' script and in 'libraries/auth/cookie.auth.lib.php'.  A
remote attacker may use these vulnerabilities to cause arbitrary HTML
and script code to be executed in a user's browser within the context
of the affected application. 

See also : 

http://sourceforge.net/tracker/index.php?func=detail&aid=1240880&group_id=23067&atid=377408
http://sourceforge.net/tracker/index.php?func=detail&aid=1265740&group_id=23067&atid=377408

Solution : 

Upgrade to phpMyAdmin 2.6.4-rc1 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in PHPMyAdmin < 2.6.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([01]\.|2\.([0-5]\.|6\.[0-3]))") security_note(port);
}

