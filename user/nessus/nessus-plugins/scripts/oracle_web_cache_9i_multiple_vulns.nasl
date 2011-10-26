#
# (C) Tenable Network Security
#


if (description) {
  script_id(18175);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1381", "CVE-2005-1382");
  script_bugtraq_id(13420, 13421, 13422);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15909");
    script_xref(name:"OSVDB", value:"15910");
  }

  name["english"] = "Oracle Application Server 9i Webcache < 9.0.4.0 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by multiple vulnerabilities. 

Description :

According to its banner, the version of Oracle Application Server 9i
Webcache installed on the remote host suffers from several flaws:

  - Arbitrary File Corruption Vulnerability
    An attacker may be able to corrupt arbitrary files on the 
    remote host by passing the filenames through the 
    'cache_dump_file' parameter of the 'webcacheadmin' script.

  - Multiple Cross-Site Scripting Vulnerabilities
    The 'webcacheadmin' script does not properly sanitize the
    'cache_dump_file' and 'PartialPageErrorPage' parameters
    before using them in dynamically generated web pages. An
    attacker may be able to exploit these flaws to conduct
    cross-site scripting attacks against the affected web site.

Reportedly, an attacker can exploit both types of vulnerabilities to
corrupt an OAS installation. 

See also : 

http://www.red-database-security.com/advisory/oracle_webcache_append_file_vulnerabilitiy.html
http://www.red-database-security.com/advisory/oracle_webcache_CSS_vulnerabilities.html

Solution : 

Contact Oracle - it's reported that they have addressed these flaws
without issuing an advisory. 

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Oracle Application Server 9i Webcache < 9.0.4.0";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/OracleApache");

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner) exit(0);


# Check the version number in the banner.
#
# nb: the Bugtraq advisories list 9.0.3.1 and below as vulnerable.
if (egrep(string:banner, pattern:"^Server:.*OracleAS-Web-Cache.*/(9\.0\.[0-3]\.[0-9]|2\..*)")) 
  security_note(port);
