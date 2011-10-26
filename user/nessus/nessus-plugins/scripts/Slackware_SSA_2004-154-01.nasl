# This script was automatically generated from the SSA-2004-154-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New mod_ssl packages are available for Slackware 8.1, 9.0, 9.1, and -current
to fix a security issue.  The packages were upgraded to mod_ssl-2.8.18-1.3.31
fixing a buffer overflow that may allow remote attackers to execute arbitrary
code via a client certificate with a long subject DN, if mod_ssl is
configured to trust the issuing CA.  Web sites running mod_ssl should upgrade
to the new set of apache and mod_ssl packages.  There are new PHP packages as
well to fix a Slackware-specific local denial-of-service issue (an additional
Slackware advisory SSA:2004-154-02 has been issued for PHP).

More details about the mod_ssl issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0488

';
if (description) {
script_id(18790);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-154-01");
script_summary("SSA-2004-154-01 mod_ssl ");
name["english"] = "SSA-2004-154-01 mod_ssl ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0488");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "apache", pkgver: "1.3.31", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 8.1
Upgrade to apache-1.3.31-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "mod_ssl", pkgver: "2.8.18_1.3.31", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 8.1
Upgrade to mod_ssl-2.8.18_1.3.31-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.3.6", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.3.6-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "apache", pkgver: "1.3.31", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 9.0
Upgrade to apache-1.3.31-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "mod_ssl", pkgver: "2.8.18_1.3.31", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 9.0
Upgrade to mod_ssl-2.8.18_1.3.31-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "php", pkgver: "4.3.6", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.0
Upgrade to php-4.3.6-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "apache", pkgver: "1.3.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 9.1
Upgrade to apache-1.3.31-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mod_ssl", pkgver: "2.8.18_1.3.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 9.1
Upgrade to mod_ssl-2.8.18_1.3.31-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "php", pkgver: "4.3.6", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.1
Upgrade to php-4.3.6-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "apache", pkgver: "1.3.31", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware -current
Upgrade to apache-1.3.31-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mod_ssl", pkgver: "2.8.18_1.3.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware -current
Upgrade to mod_ssl-2.8.18_1.3.31-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.3.6", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.3.6-i486-4 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
