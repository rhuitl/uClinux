#
# (C) Tenable Network Security
# 


if (description) {
  script_id(19775);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3078", "CVE-2005-3079");
  script_bugtraq_id(14900, 14904);

  name["english"] = "PunBB < 1.2.8 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains two PHP scripts that may allow arbitrary
code execution, local file disclosure, and cross-site scripting attacks. 

Description : 

According to its banner, the version of PunBB installed on the remote
host suffers from several flaws. 

  - A File Include Vulnerability
    The application fails to validate the 'language' 
    parameter when a user updates his profile and uses that 
    throughout the application to require PHP code in order
    to display messages. An attacker with an account on the 
    affected application may be able to exploit this issue 
    to read arbitrary and even to execute local files with 
    arbitrary PHP code subject to the privileges of the web 
    server user id.

  - A Cross-Site Scripting Vulnerability
    The application also does not sanitize input passed to
    the 'email' parameter of the 'login.php' script when
    requesting a new password, which permits cross-site 
    scripting attacks such as theft of authentication 
    cookies.

See also : 

http://www.punbb.org/changelogs/1.2.7_to_1.2.8.txt

Solution : 

Upgrade to PunBB 1.2.8 or later.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PunBB < 1.2.8";
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
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\.|1\.([01]\.|2\.[0-7]($|[^0-9])))") {
    security_note(port);
    exit(0);
  }
}
