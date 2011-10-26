#
# (C) Tenable Network Security
#


if (description) {
  script_id(19597);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2783");
  script_bugtraq_id(14688);

  name["english"] = "PHP-Fusion BBCode URL Tag Script Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-
site scripting attacks. 

Description :

According to its version number, the remote host is running a version
of PHP-Fusion that reportedly does not sufficiently sanitize input
passed in nested 'url' BBcode tags before using it in a post.  An
attacker may be able to exploit this flaw to cause arbitrary script
and HTML code to be executed in the context of a user's browser when
he/she views the malicious BBcode on the remote host. 

See also : 

http://www.securityfocus.com/archive/1/409490

Solution : 

Upgrade to PHP-Fusion 6.00.108 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for BBCode url tag script injection vulnerability in PHP-Fusion";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

  if (ver =~ "^([45][.,]|6[.,]00[.,](0|10[0-7]))") {
    security_note(port);
    exit(0);
  }
}
