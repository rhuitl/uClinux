# This script was automatically generated from the SSA-2003-336-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kernels are available for Slackware 9.1 and -current.  These
have been upgraded to Linux kernel version 2.4.23, which fixes a
bug in the kernel\'s do_brk() function that could be exploited to
gain root privileges.  These updated kernels and modules should be
installed by any sites running a 2.4 kernel earlier than 2.4.23.
Linux 2.0 and 2.2 kernels are not vulnerable.

More details about the Apache issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0961


';
if (description) {
script_id(18743);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-336-01");
script_summary("SSA-2003-336-01 Kernel security update  ");
name["english"] = "SSA-2003-336-01 Kernel security update  ";
script_name(english:name["english"]);
script_cve_id("CVE-2003-0961");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware 9.1
Upgrade to kernel-modules-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.23", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.23-noarch-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-driver", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver is vulnerable in Slackware 9.1
Upgrade to alsa-driver-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-lib", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-lib is vulnerable in Slackware 9.1
Upgrade to alsa-lib-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-oss", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-oss is vulnerable in Slackware 9.1
Upgrade to alsa-oss-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-utils", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-utils is vulnerable in Slackware 9.1
Upgrade to alsa-utils-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "alsa-driver-xfs", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver-xfs is vulnerable in Slackware 9.1
Upgrade to alsa-driver-xfs-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules-xfs", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules-xfs is vulnerable in Slackware 9.1
Upgrade to kernel-modules-xfs-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware -current
Upgrade to kernel-modules-2.4.23-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.4.23-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.23", pkgnum:  "2", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.23-noarch-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-utils", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-utils is vulnerable in Slackware -current
Upgrade to alsa-utils-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver is vulnerable in Slackware -current
Upgrade to alsa-driver-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-lib", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-lib is vulnerable in Slackware -current
Upgrade to alsa-lib-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-oss", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-oss is vulnerable in Slackware -current
Upgrade to alsa-oss-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver-xfs", pkgver: "0.9.8", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver-xfs is vulnerable in Slackware -current
Upgrade to alsa-driver-xfs-0.9.8-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules-xfs", pkgver: "2.4.23", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules-xfs is vulnerable in Slackware -current
Upgrade to kernel-modules-xfs-2.4.23-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
