# This script was automatically generated from the SSA-2004-014-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kdepim packages are available for Slackware 9.0 and 9.1 to
fix a security issue with .VCF file handling.  For Slackware -current,
a complete upgrade to kde-3.1.5 is available.


';
if (description) {
script_id(18784);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-014-01");
script_summary("SSA-2004-014-01 kdepim security update ");
name["english"] = "SSA-2004-014-01 kdepim security update ";
script_name(english:name["english"]);
script_cve_id("CVE-2003-0988");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "kdepim", pkgver: "3.1.3", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdepim is vulnerable in Slackware 9.0
Upgrade to kdepim-3.1.3-i386-2 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kdebase", pkgver: "3.1.3", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdebase is vulnerable in Slackware 9.0
Upgrade to kdebase-3.1.3-i386-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kdepim", pkgver: "3.1.4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdepim is vulnerable in Slackware 9.1
Upgrade to kdepim-3.1.4-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "arts", pkgver: "1.1.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package arts is vulnerable in Slackware -current
Upgrade to arts-1.1.5-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
