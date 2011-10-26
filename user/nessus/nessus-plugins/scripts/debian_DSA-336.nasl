# This script was automatically generated from the dsa-336
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A number of vulnerabilities have been discovered in the Linux kernel.
This advisory provides updated 2.2.20 kernel source, and binary kernel
images for the i386 architecture.  Other architectures and kernel
versions will be covered by separate advisories.
For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.2.20 version
2.2.20-5woody2 and kernel-image-i386 version 2.2.20-5woody3.
For the unstable distribution (sid) these problems are fixed in
kernel-source-2.2.25 and kernel-image-2.2.25-i386 version 2.2.25-2.
We recommend that you update your kernel packages.
NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel.  Remember to read carefully
and follow the instructions given during the kernel upgrade process.
NOTE: These kernels are not binary-compatible with the previous
version.  Any loadable modules will need to be recompiled in order to
work with the new kernel.


Solution : http://www.debian.org/security/2003/dsa-336
Risk factor : High';

if (description) {
 script_id(15173);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "336");
 script_cve_id("CVE-2002-1380", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248");
 script_bugtraq_id(4259, 6420, 6535, 7112, 7600, 7601, 7791);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA336] DSA-336-1 linux-kernel-2.2.20");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-336-1 linux-kernel-2.2.20");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.2.20', release: '3.0', reference: '2.2.20-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.2.20_2.2.20-5woody2\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20-compact is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20-compact_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20-idepci is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20-idepci_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-compact is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-compact_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-idepci is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-idepci_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-source-2.2.20', release: '3.0', reference: '2.2.20-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.2.20_2.2.20-5woody2\n');
}
if (deb_check(prefix: 'kernel-source-2.2.20', release: '3.0', reference: '2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.2.20 is vulnerable in Debian woody.\nUpgrade to kernel-source-2.2.20_2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
