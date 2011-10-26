# This script was automatically generated from the SSA-2003-308-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Apache httpd is a hypertext transfer protocol server, and is used
by over two thirds of the Internet\'s web sites.

Upgraded Apache packages are available for Slackware 8.1, 9.0, 9.1,
and -current.  These fix local vulnerabilities that could allow users
who can create or edit Apache config files to gain additional
privileges.  Sites running Apache should upgrade to the new packages.

In addition, new mod_ssl packages have been prepared for all platforms,
and new PHP packages have been prepared for Slackware 8.1, 9.0, and
- -current (9.1 already uses PHP 4.3.3).  In -current, these packages
also move the Apache module directory from /usr/libexec to
/usr/libexec/apache.  Links for all of these related packages are
provided below.

More details about the Apache issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0542


';
if (description) {
script_id(18742);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-308-01");
script_summary("SSA-2003-308-01 apache security update ");
name["english"] = "SSA-2003-308-01 apache security update ";
script_name(english:name["english"]);
script_cve_id("CVE-2003-0542");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "apache", pkgver: "1.3.29", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 8.1
Upgrade to apache-1.3.29-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "mod_ssl", pkgver: "2.8.16_1.3.29", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 8.1
Upgrade to mod_ssl-2.8.16_1.3.29-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.3.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.3.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "apache", pkgver: "1.3.29", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 9.0
Upgrade to apache-1.3.29-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "mod_ssl", pkgver: "2.8.16_1.3.29", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 9.0
Upgrade to mod_ssl-2.8.16_1.3.29-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "php", pkgver: "4.3.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.0
Upgrade to php-4.3.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "apache", pkgver: "1.3.29", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 9.1
Upgrade to apache-1.3.29-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mod_ssl", pkgver: "2.8.16_1.3.29", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 9.1
Upgrade to mod_ssl-2.8.16_1.3.29-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "apache", pkgver: "1.3.29", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware -current
Upgrade to apache-1.3.29-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mod_ssl", pkgver: "2.8.16_1.3.29", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware -current
Upgrade to mod_ssl-2.8.16_1.3.29-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.3.3", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.3.3-i486-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
