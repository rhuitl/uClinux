#
# (C) Tenable Network Security
#


if (description) {
  script_id(17301);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-0659", "CVE-2005-0673", "CVE-2005-1026");
  script_bugtraq_id(12736, 13028, 13030);

  name["english"] = "Multiple vulnerabilities in phpBB 2.0.13 and older";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

According to its banner, the remote host is running a version of phpBB
that suffers from multiple flaws:

  - A Path Disclosure Vulnerability
    A remote attacker can cause phpBB to reveal its installation
    path via a direct request to the script 'db/oracle.php'.

  - A Cross-Site Scripting Vulnerability
    The application does not properly sanitize user input before
    using it in 'privmsg.php' and 'viewtopic.php'.

  - A Privilege Escalation Vulnerability
    In 'session.php' phpBB resets the 'user_id' value when an 
    autologin fails; it does not, however, reset the 'user_level' 
    value, which remains as the account that failed the autologin.
    Since the software uses the 'user_level' parameter in some 
    cases to control access to privileged functionality, this flaw
    allows an attacker to view information, and possibly even 
    perform tasks, normally limited to administrators. 

  - SQL Injection Vulnerabilities
    The DLMan Pro and LinksLinks Pro mods, if installed, reportedly 
    fail to properly sanitize user input to the 'file_id' parameter
    of the 'dlman.php' script and the 'id' parameter of the
    'links.php' script respectively before using it in an SQL 
    query. This may allow an attacker to pass malicious input
    to database queries.

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-03/0059.html
http://archives.neohapsis.com/archives/bugtraq/2005-03/0085.html
http://archives.neohapsis.com/archives/bugtraq/2005-04/0056.html
http://archives.neohapsis.com/archives/bugtraq/2005-04/0063.html

Solution : 

Upgrade to a version after phpBB 2.0.13 and disable the DLMan Pro and
LinksLinks Pro mods. 

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in phpBB 2.0.13 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-3])([^0-9]|$))") 
    security_warning(port);
}
