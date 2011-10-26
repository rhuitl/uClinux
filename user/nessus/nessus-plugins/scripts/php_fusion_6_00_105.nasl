#
# (C) Tenable Network Security
#


if (description) {
  script_id(19232);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2074", "CVE-2005-2075");
  script_bugtraq_id(14066);

  name["english"] = "PHP-Fusion <= 6.00.105 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from two
vulnerabilities. 

Description :

According to its banner, the remote host is running a version of
PHP-Fusion that suffers from two vulnerabilities :

  - An Information Disclosure Vulnerability
    PHP Fusion stores database backups in a known location 
    within the web server's documents directory. An attacker
    may be able to retrieve these backups and obtain 
    password hashes or other sensitive information from the
    database.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject malicious HTML and script code 
    into the 'news_body', 'article_description', and the 
    'article_body' parameters when submitting news or an
    article.

See also :

http://dark-assassins.com/forum/viewtopic.php?t=142
http://dark-assassins.com/forum/viewtopic.php?t=145

Solution : 

Upgrade to PHP-Fusion 6.00.106 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PHP-Fusion <= 6.00.105";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family("CGI abuses");

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

  # nb: 6.00.105 is known to be affected; other versions may also be.
  if (ver =~ "^([0-5][.,]|6[.,]00[.,](0|10[0-5]))") security_warning(port);
}
