# This script was automatically generated from the dsa-270
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The kernel module loader in Linux 2.2 and Linux 2.4 kernels has a flaw
in ptrace.  This hole allows local users to obtain root privileges by
using ptrace to attach to a child process that is spawned by the
kernel.  Remote exploitation of this hole is not possible.
This advisory only covers kernel packages for the big and little endian MIPS
architectures.  Other architectures will be covered by separate advisories.
For the stable distribution (woody) this problem has been fixed in version
2.4.17-0.020226.2.woody1 of kernel-patch-2.4.17-mips (mips+mipsel) and in
version 2.4.19-0.020911.1.woody1 of kernel-patch-2.4.19-mips (mips only).
The old stable distribution (potato) is not affected by this problem
for these architectures since mips and mipsel were first released with
Debian GNU/Linux 3.0 (woody).
For the unstable distribution (sid) this problem has been fixed in
version 2.4.19-0.020911.6 of kernel-patch-2.4.19-mips (mips+mipsel).
We recommend that you upgrade your kernel-images packages immediately.


Solution : http://www.debian.org/security/2003/dsa-270
Risk factor : High';

if (description) {
 script_id(15107);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "270");
 script_cve_id("CVE-2003-0127");
 script_bugtraq_id(7112);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA270] DSA-270-1 linux-kernel-mips");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-270-1 linux-kernel-mips");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-0.020226.2.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17_2.4.17-0.020226.2.woody1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.19', release: '3.0', reference: '2.4.19-0.020911.1.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.19 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.19_2.4.19-0.020911.1.woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r3k-kn02', release: '3.0', reference: '2.4.17-0.020226.2.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r3k-kn02 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r3k-kn02_2.4.17-0.020226.2.woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-ip22_2.4.17-0.020226.2.woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-kn04', release: '3.0', reference: '2.4.17-0.020226.2.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-kn04 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-kn04_2.4.17-0.020226.2.woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r5k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r5k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r5k-ip22_2.4.17-0.020226.2.woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.19-r4k-ip22', release: '3.0', reference: '2.4.19-0.020911.1.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.19-r4k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.19-r4k-ip22_2.4.19-0.020911.1.woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.19-r5k-ip22', release: '3.0', reference: '2.4.19-0.020911.1.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.19-r5k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.19-r5k-ip22_2.4.19-0.020911.1.woody1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-mips_2.4.17-0.020226.2.woody1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.19-mips', release: '3.0', reference: '2.4.19-0.020911.1.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.19-mips is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.19-mips_2.4.19-0.020911.1.woody1\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.0', reference: '2.4.17-0.020226.2.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.0.\nUpgrade to mips-tools_2.4.17-0.020226.2.woody1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips,', release: '3.1', reference: '2.4.19-0.020911')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips, is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.17-mips,_2.4.19-0.020911\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips,', release: '3.0', reference: '2.4.17-0.020226.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips, is vulnerable in Debian woody.\nUpgrade to kernel-patch-2.4.17-mips,_2.4.17-0.020226.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
