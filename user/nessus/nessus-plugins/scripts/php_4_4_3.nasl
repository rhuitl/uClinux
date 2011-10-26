#
# (C) Tenable Network Security
#


if (description) {
  script_id(22268);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2006-0996",
    "CVE-2006-1490", 
    "CVE-2006-1494", 
    "CVE-2006-1608",
    "CVE-2006-1990",
    "CVE-2006-1991",
    "CVE-2006-2563",
    "CVE-2006-2660",
    "CVE-2006-3011",
    "CVE-2006-3016", 
    "CVE-2006-3017", 
    "CVE-2006-3018"
  );
  script_bugtraq_id(17296, 17362, 17439, 17843, 18116, 18645);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"24484");
    script_xref(name:"OSVDB", value:"25253");
    script_xref(name:"OSVDB", value:"25254");
    script_xref(name:"OSVDB", value:"25255");
    script_xref(name:"OSVDB", value:"26827");
  }

  script_name(english:"PHP < 4.4.3 / 5.1.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  desc = "
Synopsis :

The remote web server uses a version of PHP that is affected by
multiple flaws. 

Description :

According to its banner, the version of PHP installed on the remote
host is older than 4.4.3 / 5.1.4.  Such versions may be affected by
several issues, including a buffer overflow, heap corruption, and a
flaw by which a variable may survive a call to 'unset()'. 

See also :

http://www.securityfocus.com/archive/1/20060409192313.20536.qmail@securityfocus.com
http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html
http://www.securityfocus.com/archive/1/archive/1/442437/100/0/threaded
http://www.php.net/release_4_4_3.php
http://www.php.net/release_5_1_3.php
http://www.php.net/release_5_1_4.php

Solution :

Upgrade to PHP version 4.4.3 / 5.1.4 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");
include("http_func.inc");


# Banner checks of PHP are prone to false-positives so we only
# run the check if reporting is paranoid.
if (report_paranoia <= 1) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


banner = get_http_banner(port:port);
if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/(3\.|4\.([0-3]\.|4\.[0-2])|5\.(0\.|1[0-3]))") {
    security_warning(port);
    exit(0);
  }
}
