#
# (C) Tenable Network Security
#


if (description) {
  script_id(20111);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2491", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390");
  script_bugtraq_id(14620, 15248, 15249, 15250);

  script_name(english:"PHP < 4.4.1 / 5.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in PHP < 4.4.1 / 5.0.6");
 
  desc = "
Synopsis :

The remote web server uses a version of PHP that is affected by
multiple flaws. 

Description :

According to its banner, the version of PHP installed on the remote
host is older than 4.4.1 or 5.0.6.  Such versions fail to protect the
'$GLOBALS' superglobals variable from being overwritten due to
weaknesses in the file upload handling code as well as the 'extract()'
and 'import_request_variables()' functions.  Depending on the nature
of the PHP applications on the affected host, exploitation of this
issue may lead to any number of attacks, including arbitrary code
execution. 

In addition, these versions may enable an attacker to exploit an
integer overflow flaw in certain certain versions of the PCRE library,
to enable PHP's 'register_globals' setting even if explicitly disabled
in the configuration, and to launch cross-site scripting attacks
involving PHP's 'phpinfo()' function. 

See also :

http://www.hardened-php.net/advisory_182005.77.html
http://www.hardened-php.net/advisory_182005.78.html
http://www.hardened-php.net/advisory_202005.79.html
http://www.php.net/release_4_4_1.php

Solution : 

Upgrade to PHP version 4.4.1 / 5.0.6 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# If we're being paranoid...
if (report_paranoia > 1) {
  banner = get_http_banner(port:port);
  if (!banner) exit(0);

  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/(3\.|4\.([0-3]\.|4\.0)|5\.0\.[0-5])") {
    security_warning(port);
    exit(0);
  }
}
