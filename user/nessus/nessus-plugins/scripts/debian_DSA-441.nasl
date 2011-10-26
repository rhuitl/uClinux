# This script was automatically generated from the dsa-441
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Starzetz and Wojciech Purczynski of isec.pl <a
href="http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt">discovered</a> a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call.  Due to missing function return value check
of internal functions a local attacker can gain root privileges.
For the stable distribution (woody) this problem has been fixed in
version 2.4.17-0.020226.2.woody5 for mips and mipsel kernel images.
Other architectures will probably mentioned in a separate advisory or
are not affected (m68k).
For the unstable distribution (sid) this problem will be fixed soon
with the next upload of a 2.4.19 kernel image and in version
2.4.22-0.030928.3 for 2.4.22 for the mips and mipsel architectures.
This problem is also fixed in the upstream version of Linux 2.4.25 and
2.6.3.
We recommend that you upgrade your Linux kernel packages immediately.
Vulnerability matrix for CVE-2004-0077


Solution : http://www.debian.org/security/2004/dsa-441
Risk factor : High';

if (description) {
 script_id(15278);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "441");
 script_cve_id("CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA441] DSA-441-1 linux-kernel-2.4.17-mips+mipsel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-441-1 linux-kernel-2.4.17-mips+mipsel");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-0.020226.2.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17_2.4.17-0.020226.2.woody5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r3k-kn02', release: '3.0', reference: '2.4.17-0.020226.2.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r3k-kn02 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r3k-kn02_2.4.17-0.020226.2.woody5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-ip22_2.4.17-0.020226.2.woody5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-kn04', release: '3.0', reference: '2.4.17-0.020226.2.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-kn04 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-kn04_2.4.17-0.020226.2.woody5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r5k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r5k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r5k-ip22_2.4.17-0.020226.2.woody5\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-mips_2.4.17-0.020226.2.woody5\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.0', reference: '2.4.17-0.020226.2.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.0.\nUpgrade to mips-tools_2.4.17-0.020226.2.woody5\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips is vulnerable in Debian woody.\nUpgrade to kernel-patch-2.4.17-mips_2.4.17-0.020226.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
