# This script was automatically generated from the SSA-2004-236-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='

New Qt packages are available for Slackware 9.0, 9.1, 10.0, and -current to
fix security issues.  Bugs in the routines that handle PNG, BMP, GIF, and
JPEG images may allow an attacker to cause unauthorized code to execute when
a specially crafted image file is processed.  These flaws may also cause
crashes that lead to a denial of service.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0691
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0692
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0693


';
if (description) {
script_id(18767);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-236-01");
script_summary("SSA-2004-236-01 Qt ");
name["english"] = "SSA-2004-236-01 Qt ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0691","CVE-2004-0692","CVE-2004-0693");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "qt", pkgver: "3.1.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package qt is vulnerable in Slackware 9.0
Upgrade to qt-3.1.2-i486-4 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "qt", pkgver: "3.2.1", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package qt is vulnerable in Slackware 9.1
Upgrade to qt-3.2.1-i486-2 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "qt", pkgver: "3.3.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package qt is vulnerable in Slackware 10.0
Upgrade to qt-3.3.3-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "qt", pkgver: "3.3.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package qt is vulnerable in Slackware -current
Upgrade to qt-3.3.3-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
