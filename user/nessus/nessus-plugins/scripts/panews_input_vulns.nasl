#
# (C) Tenable Network Security
#


if (description) {
  script_id(17574);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-0646", "CVE-2005-0647");
  script_bugtraq_id(12687);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15452");

  name["english"] = "paNews Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple flaws. 

Description :

The remote host is running a version of paNews that suffers from the
following vulnerabilities:

  - SQL Injection Issue in the 'login' method of includes/auth.php.
    A remote attacker can leverage this vulnerability to add 
    users with arbitrary privileges.

  - Local Script Injection Vulnerability in includes/admin_setup.php.
    A user defined to the system (see above) can inject arbitrary
    PHP code into paNews' config.php via the 'comments' and 
    'autapprove' parameters of the 'admin_setup.php'
    script.

See also :

http://www.kernelpanik.org/docs/kernelpanik/panews.txt
http://archives.neohapsis.com/archives/bugtraq/2005-03/0006.html

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects input validation vulnerabilities in paNews";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
  script_family(english:"CGI abuses");
 
  script_dependencies("panews_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!port) exit(0);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/panews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver && ver =~  "^([0-1]\.|2\.0b[0-4])$") security_hole(port);
}
