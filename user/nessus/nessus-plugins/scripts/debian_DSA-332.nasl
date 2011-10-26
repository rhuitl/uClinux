# This script was automatically generated from the dsa-332
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A number of vulnerabilities have been discovered in the Linux kernel.
This advisory provides corrected source code for Linux 2.4.17, and
corrected binary kernel images for the mips and mipsel architectures.
Other versions and architectures will be covered by separate
advisories.
For the stable distribution (woody), these problems have been fixed in
kernel-source-2.4.17 version 2.4.17-1woody1 and
kernel-patch-2.4.17-mips version 2.4.17-0.020226.2.woody2.
For the unstable distribution (sid) these problems are fixed in
kernel-source-2.4.20 version 2.4.20-8.
We recommend that you update your kernel packages.
NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel.  Remember to read carefully
and follow the instructions given during the kernel upgrade process.


Solution : http://www.debian.org/security/2003/dsa-332
Risk factor : High';

if (description) {
 script_id(15169);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "332");
 script_cve_id("CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");
 script_bugtraq_id(4259, 6535, 7112, 7600, 7601, 7791, 7793);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA332] DSA-332-1 linux-kernel-2.4.17");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-332-1 linux-kernel-2.4.17");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.17', release: '3.0', reference: '2.4.17-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.17_2.4.17-1woody1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-0.020226.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17_2.4.17-0.020226.2.woody2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r3k-kn02', release: '3.0', reference: '2.4.17-0.020226.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r3k-kn02 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r3k-kn02_2.4.17-0.020226.2.woody2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-ip22_2.4.17-0.020226.2.woody2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-kn04', release: '3.0', reference: '2.4.17-0.020226.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-kn04 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-kn04_2.4.17-0.020226.2.woody2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r5k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r5k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r5k-ip22_2.4.17-0.020226.2.woody2\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-mips_2.4.17-0.020226.2.woody2\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17', release: '3.0', reference: '2.4.17-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17_2.4.17-1woody1\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.0', reference: '2.4.17-0.020226.2.woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.0.\nUpgrade to mips-tools_2.4.17-0.020226.2.woody2\n');
}
if (deb_check(prefix: 'mkcramfs', release: '3.0', reference: '2.4.17-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mkcramfs is vulnerable in Debian 3.0.\nUpgrade to mkcramfs_2.4.17-1woody1\n');
}
if (deb_check(prefix: 'kernel-source-2.4.20', release: '3.1', reference: '2.4.20-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.20 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.4.20_2.4.20-8\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17', release: '3.0', reference: '2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17 is vulnerable in Debian woody.\nUpgrade to kernel-source-2.4.17_2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
