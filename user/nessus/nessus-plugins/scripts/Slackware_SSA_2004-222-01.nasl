# This script was automatically generated from the SSA-2004-222-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New libpng packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
and -current to fix security issues.  These issues could cause program crashes,
or possibly allow arbitrary code embedded in a malicious PNG image to execute.
The PNG library is widely used within the system, so all sites should upgrade
to the new libpng package.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0597
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0598
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0599

';
if (description) {
script_id(18781);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-222-01");
script_summary("SSA-2004-222-01 libpng ");
name["english"] = "SSA-2004-222-01 libpng ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0597","CVE-2004-0598","CVE-2004-0599");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "libpng", pkgver: "1.2.5", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libpng is vulnerable in Slackware 8.1
Upgrade to libpng-1.2.5-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "libpng", pkgver: "1.2.5", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libpng is vulnerable in Slackware 9.0
Upgrade to libpng-1.2.5-i386-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "libpng", pkgver: "1.2.5", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libpng is vulnerable in Slackware 9.1
Upgrade to libpng-1.2.5-i486-3 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "libpng", pkgver: "1.2.5", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libpng is vulnerable in Slackware 10.0
Upgrade to libpng-1.2.5-i486-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "libpng", pkgver: "1.2.5", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libpng is vulnerable in Slackware -current
Upgrade to libpng-1.2.5-i486-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
