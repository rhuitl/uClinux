#
# (C) Tenable Network Security
#


if (description) {
  script_id(18612);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2153", "CVE-2005-2154");
  script_bugtraq_id(14127);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17714");
    script_xref(name:"OSVDB", value:"17715");
  }

  name["english"] = "osTicket <= 1.3.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple vulnerabilities. 

Description :

The version of osTicket installed on the remote host suffers from
several vulnerabilities, including:

  - A Local File Include Vulnerability
    The application fails to sanitize user-supplied input
    to the 'inc' parameter in the 'view.php' script. An 
    attacker may be able to exploit this flaw to run 
    arbitrary PHP code found in files on the remote host 
    provided PHP's 'register_globals' setting is enabled.

  - A SQL Injection Vulnerabilitie
    An authenticated attacker can affect SQL queries via
    POST queries due to a failure of the application to
    filter input to the 'ticket' variable in the 
    'class.ticket.php' code library.

See also : 

http://www.osticket.com/forums/showthread.php?t=1283
http://www.securityfocus.com/archive/1/403990/30/0/threaded
http://www.osticket.com/news/sec,05,01.html

Solution : 

Apply the security update for version 1.3.1.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks version of osTicket";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("osticket_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


# nb: the vendor has issued a patch that doesn't change the version.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/osticket"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Check the version number -- both flaws require authentication.
  if (ver && ver  =~ "^(0\.|1\.([01]\.|2\.[0-7]|3\.[01]))") {
    security_note(port);
    exit(0);
  }
}
