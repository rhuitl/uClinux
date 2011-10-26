# This script was automatically generated from the SSA-2005-242-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New PHP packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
and -current to fix security issues.  PHP has been relinked with the
shared PCRE library to fix an overflow issue with PHP\'s builtin PRCE
code, and PEAR::XMLRPC has been upgraded to version 1.4.0 which
eliminates the eval() function.  The eval() function is believed to be
insecure as implemented, and would be difficult to secure.

Note that these new packages now require that the PCRE package be
installed, so be sure to get the new package from the patches/packages/
directory if you don\'t already have it.  A new version of this (6.3)
was also issued today, so be sure that is the one you install.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2491
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2498

';
if (description) {
script_id(19859);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-242-02");
script_summary("SSA-2005-242-02 PHP ");
name["english"] = "SSA-2005-242-02 PHP ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-2491","CVE-2005-2498");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.3.11", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.3.11-i386-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "php", pkgver: "4.3.11", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.0
Upgrade to php-4.3.11-i386-4 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "php", pkgver: "4.3.11", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.1
Upgrade to php-4.3.11-i486-4 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "php", pkgver: "4.3.11", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 10.0
Upgrade to php-4.3.11-i486-3 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "php", pkgver: "4.3.11", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 10.1
Upgrade to php-4.3.11-i486-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.4.0", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.4.0-i486-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
