# This script was automatically generated from the SSA-2004-043-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New XFree86 base packages are available for Slackware 8.1, 9.0,
9.1, and -current.  These fix overflows which could possibly be
exploited to gain unauthorized root access.  All sites running
XFree86 should upgrade to the new package.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0083
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0084
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0106


';
if (description) {
script_id(18771);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-043-02");
script_summary("SSA-2004-043-02 XFree86 security update ");
name["english"] = "SSA-2004-043-02 XFree86 security update ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0083","CVE-2004-0084","CVE-2004-0106");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "xfree86", pkgver: "4.2.1", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xfree86 is vulnerable in Slackware 8.1
Upgrade to xfree86-4.2.1-i386-3 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "xfree86", pkgver: "4.3.0", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xfree86 is vulnerable in Slackware 9.0
Upgrade to xfree86-4.3.0-i386-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "xfree86", pkgver: "4.3.0", pkgnum:  "6", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xfree86 is vulnerable in Slackware 9.1
Upgrade to xfree86-4.3.0-i486-6 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xfree86", pkgver: "4.3.0", pkgnum:  "6", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xfree86 is vulnerable in Slackware -current
Upgrade to xfree86-4.3.0-i486-6 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
