# This script was automatically generated from the SSA-2004-006-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kernels are available for Slackware 9.0, 9.1 and -current.
The 9.1 and -current kernels have been upgraded to 2.4.24, and a
fix has been backported to the 2.4.21 kernels in Slackware 9.0
to fix a bounds-checking problem in the kernel\'s mremap() call
which could be used by a local attacker to gain root privileges.
Sites should upgrade to the 2.4.24 kernel and kernel modules.
After installing the new kernel, be sure to run \'lilo\'.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0985


';
if (description) {
script_id(18795);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-006-01");
script_summary("SSA-2004-006-01 Kernel security update  ");
name["english"] = "SSA-2004-006-01 Kernel security update  ";
script_name(english:name["english"]);
script_cve_id("CVE-2003-0985");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "kernel-ide", pkgver: "2.4.21", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 9.0
Upgrade to kernel-ide-2.4.21-i486-3 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-source", pkgver: "2.4.21", pkgnum:  "3", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 9.0
Upgrade to kernel-source-2.4.21-noarch-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.24-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware 9.1
Upgrade to kernel-modules-2.4.24-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.24-noarch-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-driver", pkgver: "0.9.8", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver is vulnerable in Slackware 9.1
Upgrade to alsa-driver-0.9.8-i486-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-driver-xfs", pkgver: "0.9.8", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver-xfs is vulnerable in Slackware 9.1
Upgrade to alsa-driver-xfs-0.9.8-i486-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules-xfs", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules-xfs is vulnerable in Slackware 9.1
Upgrade to kernel-modules-xfs-2.4.24-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.24-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware -current
Upgrade to kernel-modules-2.4.24-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.4.24-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.24-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver", pkgver: "1.0.0rc2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver is vulnerable in Slackware -current
Upgrade to alsa-driver-1.0.0rc2-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver-xfs", pkgver: "1.0.0rc2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver-xfs is vulnerable in Slackware -current
Upgrade to alsa-driver-xfs-1.0.0rc2-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules-xfs", pkgver: "2.4.24", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules-xfs is vulnerable in Slackware -current
Upgrade to kernel-modules-xfs-2.4.24-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
