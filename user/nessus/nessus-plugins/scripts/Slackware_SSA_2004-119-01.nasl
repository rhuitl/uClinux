# This script was automatically generated from the SSA-2004-119-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kernel packages are available for Slackware 9.1 and -current to
fix security issues.  Also available are new kernel modules packages
(including alsa-driver), and a new version of the hotplug package
for Slackware 9.1 containing some fixes for using 2.4.26 (and 2.6.x)
kernel modules.

The most serious of the fixed issues is an overflow in ip_setsockopt(),
which could allow a local attacker to gain root access, or to crash or
reboot the machine.  This bug affects 2.4 kernels from 2.4.22 - 2.4.25.
Any sites running one of those kernel versions should upgrade right
away.  After installing the new kernel, be sure to run \'lilo\'.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0394
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0424


';
if (description) {
script_id(18792);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-119-01");
script_summary("SSA-2004-119-01 kernel security updates ");
name["english"] = "SSA-2004-119-01 kernel security updates ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0394","CVE-2004-0424");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.1", pkgname: "alsa-driver", pkgver: "0.9.8", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver is vulnerable in Slackware 9.1
Upgrade to alsa-driver-0.9.8-i486-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "hotplug", pkgver: "2004_01_05", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package hotplug is vulnerable in Slackware 9.1
Upgrade to hotplug-2004_01_05-noarch-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 9.1
Upgrade to kernel-ide-2.4.26-i486-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-headers", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-headers is vulnerable in Slackware 9.1
Upgrade to kernel-headers-2.4.26-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-modules", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware 9.1
Upgrade to kernel-modules-2.4.26-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 9.1
Upgrade to kernel-source-2.4.26-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-ide", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware -current
Upgrade to kernel-ide-2.4.26-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-modules", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware -current
Upgrade to kernel-modules-2.4.26-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-headers", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-headers is vulnerable in Slackware -current
Upgrade to kernel-headers-2.4.26-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kernel-source", pkgver: "2.4.26", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware -current
Upgrade to kernel-source-2.4.26-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "alsa-driver", pkgver: "1.0.4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package alsa-driver is vulnerable in Slackware -current
Upgrade to alsa-driver-1.0.4-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
