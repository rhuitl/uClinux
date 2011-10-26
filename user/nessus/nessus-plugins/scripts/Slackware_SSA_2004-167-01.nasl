# This script was automatically generated from the SSA-2004-167-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kernel packages are available for Slackware 8.1, 9.0, 9.1,
and -current to fix a denial of service security issue.  Without
a patch to asm-i386/i387.h, a local user can crash the machine.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0554

';
if (description) {
script_id(18791);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-167-01");
script_summary("SSA-2004-167-01 kernel DoS ");
name["english"] = "SSA-2004-167-01 kernel DoS ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0554");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "kernel-ide", pkgver: "2.4.18", pkgnum:  "6", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 8.1
Upgrade to kernel-ide-2.4.18-i386-6 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "kernel-source", pkgver: "2.4.18", pkgnum:  "7", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 8.1
Upgrade to kernel-source-2.4.18-noarch-7 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-ide", pkgver: "2.4.21", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 9.0
Upgrade to kernel-ide-2.4.21-i486-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-source", pkgver: "2.4.21", pkgnum:  "4", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 9.0
Upgrade to kernel-source-2.4.21-noarch-4 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.26-i486-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.26-noarch-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.26-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.4.26", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.4.26-i386-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "4", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.26-noarch-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-generic", pkgver: "2.6.6", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-generic is vulnerable in Slackware -current
Upgrade to kernel-generic-2.6.6-i486-5 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.6.6", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.6.6-i386-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.6.6", pkgnum:  "3", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.6.6-noarch-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
