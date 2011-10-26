# This script was automatically generated from the SSA-2006-045-09
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New xpdf packages are available for Slackware 9.0, 9.1, 10.0, 10.1, 10.2,
and -current to fix security issues.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3191
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3192
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3193
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3624
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3625
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3626
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3627
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3628
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0301


';
if (description) {
script_id(20920);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-045-09");
script_summary("SSA-2006-045-09 xpdf ");
name["english"] = "SSA-2006-045-09 xpdf ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-3191","CVE-2005-3192","CVE-2005-3193","CVE-2005-3624","CVE-2005-3625","CVE-2005-3626","CVE-2005-3627","CVE-2005-3628","CVE-2006-0301");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "xpdf", pkgver: "3.01", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xpdf is vulnerable in Slackware 9.0
Upgrade to xpdf-3.01-i386-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "xpdf", pkgver: "3.01", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xpdf is vulnerable in Slackware 9.1
Upgrade to xpdf-3.01-i486-3 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "xpdf", pkgver: "3.01", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xpdf is vulnerable in Slackware 10.0
Upgrade to xpdf-3.01-i486-3 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "xpdf", pkgver: "3.01", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xpdf is vulnerable in Slackware 10.2
Upgrade to xpdf-3.01-i486-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xpdf", pkgver: "3.01", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xpdf is vulnerable in Slackware -current
Upgrade to xpdf-3.01-i486-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
