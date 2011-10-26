# This script was automatically generated from the SSA-2005-310-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New KOffice packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 
and -current to fix a security issue with KWord.  A buffer overflow in
the RTF import functionality could result in the execution of arbitrary
code.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2971


';
if (description) {
script_id(20150);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-310-02");
script_summary("SSA-2005-310-02 KOffice/KWord ");
name["english"] = "SSA-2005-310-02 KOffice/KWord ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-2971");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.1", pkgname: "koffice", pkgver: "1.2.1", pkgnum:  "6", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package koffice is vulnerable in Slackware 9.1
Upgrade to koffice-1.2.1-i486-6 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "koffice", pkgver: "1.3.1", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package koffice is vulnerable in Slackware 10.0
Upgrade to koffice-1.3.1-i486-4 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "koffice", pkgver: "1.3.5", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package koffice is vulnerable in Slackware 10.1
Upgrade to koffice-1.3.5-i486-3 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "koffice", pkgver: "1.4.1", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package koffice is vulnerable in Slackware 10.2
Upgrade to koffice-1.4.1-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "koffice", pkgver: "1.4.1", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package koffice is vulnerable in Slackware -current
Upgrade to koffice-1.4.1-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
