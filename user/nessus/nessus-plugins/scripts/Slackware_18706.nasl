# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='Several security updates are now available for Slackware 8.1, including
updated packages for Apache, glibc, mod_ssl, openssh, openssl, and php.

';
if (description) {
script_id(18706);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_summary("SSA Security updates for Slackware 8.1");
name["english"] = "SSA- Security updates for Slackware 8.1";
script_name(english:name["english"]);script_cve_id("CVE-2002-0653","CVE-2002-0658","CVE-2002-0659");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "apache", pkgver: "1.3.26", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 8.1
Upgrade to apache-1.3.26-i386-2 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "glibc", pkgver: "2.2.5", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package glibc is vulnerable in Slackware 8.1
Upgrade to glibc-2.2.5-i386-3 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "glibc-solibs", pkgver: "2.2.5", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package glibc-solibs is vulnerable in Slackware 8.1
Upgrade to glibc-solibs-2.2.5-i386-3 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "mod_ssl", pkgver: "2.8.10_1.3.26", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 8.1
Upgrade to mod_ssl-2.8.10_1.3.26-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssh", pkgver: "3.4p1", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware 8.1
Upgrade to openssh-3.4p1-i386-2 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssl", pkgver: "0.9.6e", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl is vulnerable in Slackware 8.1
Upgrade to openssl-0.9.6e-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssl-solibs", pkgver: "0.9.6e", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl-solibs is vulnerable in Slackware 8.1
Upgrade to openssl-solibs-0.9.6e-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.2.2", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.2.2-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
