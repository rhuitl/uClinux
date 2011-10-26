#
# (C) Tenable Network Security
#


if (description) {
  script_id(19311);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2401", "CVE-2005-3159");
  script_bugtraq_id(14332, 14489);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18111");
  }

  name["english"] = "PHP-Fusion <= 6.00.106 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that suffer from SQL
injection and cross-site scripting flaws. 

Description :

According to its banner, the remote host is running a version of
PHP-Fusion that suffers from multiple vulnerabilities :

  - SQL Injection Vulnerability
    The application fails to sanitize user-supplied input to the 
    'msg_view' parameter of the 'messages.php' script before 
    using it in database queries. Exploitation requires that an 
    attacker first authenticate.

  - HTML Injection Vulnerability
    An attacker can inject malicious CSS (Cascading Style Sheets)
    codes through [color] tags, thereby affecting how the site is 
    rendered whenever users view specially-crafted posts. 

See also : 

http://secure4arab.com/forum/showthread.php?t=3506

Solution : 

Upgrade to PHP-Fusion 6.00.107 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PHP-Fusion <= 6.00.106";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/php-fusion"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([45][.,]|6[.,]00[.,](0|10\[0-6]))") {
    security_note(port);
    exit(0);
  }
}
