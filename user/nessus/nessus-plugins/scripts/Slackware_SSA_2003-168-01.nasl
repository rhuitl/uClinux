# This script was automatically generated from the SSA-2003-168-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Precompiled Linux 2.4.21 kernels and source packages are now available for
Slackware 9.0 and -current.  These provide an improved version of the
ptrace fix that had been applied to 2.4.20 in Slackware 9.0 (for example,
command line options now appear correctly when root does \'ps ax\'), and
fix a potential denial of service problem with netfilter.

';
if (description) {
script_id(18741);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-168-01");
script_summary("SSA-2003-168-01 2.4.21 kernels available ");
name["english"] = "SSA-2003-168-01 2.4.21 kernels available ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "kernel-headers", pkgver: "2.4.21", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-headers is vulnerable in Slackware 9.0
Upgrade to kernel-headers-2.4.21-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-ide", pkgver: "2.4.21", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-ide is vulnerable in Slackware 9.0
Upgrade to kernel-ide-2.4.21-i486-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-modules", pkgver: "2.4.21", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware 9.0
Upgrade to kernel-modules-2.4.21-i486-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-modules", pkgver: "2.4.21_xfs", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-modules is vulnerable in Slackware 9.0
Upgrade to kernel-modules-2.4.21_xfs-i486-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "kernel-source", pkgver: "2.4.21", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kernel-source is vulnerable in Slackware 9.0
Upgrade to kernel-source-2.4.21-noarch-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
