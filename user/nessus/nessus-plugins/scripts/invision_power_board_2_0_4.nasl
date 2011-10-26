#
# (C) Tenable Network Security
#


if (description) {
  script_id(18203);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1597", "CVE-2005-1598");
  script_bugtraq_id(13529, 13532, 13534, 13375);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16297");
    script_xref(name:"OSVDB", value:"16298");
  }

  name["english"] = "Invision Power Board < 2.0.4 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
multiple attacks. 

Description :

According to its banner, the version of Invision Power Board on the
remote host suffers from multiple vulnerabilities :

  - SQL Injection Vulnerability
    The application fails to sanitize user-input supplied 
    through the 'pass_hash' cookie in the 'sources/login.php'
    script, which can be exploited to affect database
    queries, potentially revealing sensitive information.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code 
    through the 'highlite' parameter of the 
    'sources/search.php' and 'sources/topics.php' scripts.

See also : 

http://www.gulftech.org/?node=research&article_id=00073-05052005
http://archives.neohapsis.com/archives/bugtraq/2005-05/0071.html
http://archives.neohapsis.com/archives/bugtraq/2005-07/0257.html

Solution : 

Upgrade to Invision Power Board 2.0.4 or later.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Invision Power Board < 2.0.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([01]\.|2\.0\.[0-3][^0-9]*)") security_warning(port);
}
