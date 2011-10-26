# This script was automatically generated from the SSA-2004-133-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New apache packages are available for Slackware 8.1, 9.0, 9.1, and -current to
fix security issues.  These include a possible denial-of-service attack as well
as the ability to possible pipe shell escapes through Apache\'s errorlog (which
could create an exploit if the error log is read in a terminal program that
does not filter such escapes).  We recommend that sites running Apache upgrade
to the new Apache package.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0987
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0020
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0174
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0993


';
if (description) {
script_id(18787);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-133-01");
script_summary("SSA-2004-133-01 apache ");
name["english"] = "SSA-2004-133-01 apache ";
script_name(english:name["english"]);
script_cve_id("CVE-2003-0020","CVE-2003-0987","CVE-2003-0993","CVE-2004-0174");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "apache", pkgver: "1.3.29", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 8.1
Upgrade to apache-1.3.29-i386-2 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "apache", pkgver: "1.3.29", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 9.0
Upgrade to apache-1.3.29-i386-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "apache", pkgver: "1.3.29", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware 9.1
Upgrade to apache-1.3.29-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "apache", pkgver: "1.3.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware -current
Upgrade to apache-1.3.31-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mod_ssl", pkgver: "2.8.17_1.3.31", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware -current
Upgrade to mod_ssl-2.8.17_1.3.31-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.3.6", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.3.6-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
