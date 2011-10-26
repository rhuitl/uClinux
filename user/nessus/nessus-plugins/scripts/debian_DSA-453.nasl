# This script was automatically generated from the dsa-453
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
the mremap(2) system call.  Due to flushing the TLB (Translation
Lookaside Buffer, an address cache) too early it is possible for an
attacker to trigger a local root exploit.
The attack vectors for 2.4.x and 2.2.x kernels are exclusive for the
respective kernel series, though.  We formerly believed that the
exploitable vulnerability in 2.4.x does not exist in 2.2.x which is
still true.  However, it turned out that a second (sort of)
vulnerability is indeed exploitable in 2.2.x, but not in 2.4.x, with a
different exploit, of course.
For the stable distribution (woody) this problem has been fixed in
the following versions and architectures:
For the unstable distribution (sid) this problem will be fixed soon
for the architectures that still ship a 2.2.x kernel package.
We recommend that you upgrade your Linux kernel package.
Vulnerability matrix for CVE-2004-0077


Solution : http://www.debian.org/security/2004/dsa-453
Risk factor : High';

if (description) {
 script_id(15290);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "453");
 script_cve_id("CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA453] DSA-453-1 linux-kernel-2.2.20-i386+m68k+powerpc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-453-1 linux-kernel-2.2.20-i386+m68k+powerpc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.2.20', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.2.20_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20', release: '3.0', reference: '2.2.20-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20_2.2.20-3woody1\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20-compact is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20-compact_2.2.20-5woody5\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20-idepci is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20-idepci_2.2.20-5woody5\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20-reiserfs', release: '3.0', reference: '2.2.20-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20-reiserfs is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20-reiserfs_2.2.20-4woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20', release: '3.0', reference: '2.2.20-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20_2.2.20-5woody5\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-amiga', release: '3.0', reference: '2.2.20-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-amiga is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-amiga_2.2.20-4\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-atari', release: '3.0', reference: '2.2.20-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-atari is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-atari_2.2.20-3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-bvme6000', release: '3.0', reference: '2.2.20-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-bvme6000 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-bvme6000_2.2.20-3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-chrp', release: '3.0', reference: '2.2.20-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-chrp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-chrp_2.2.20-3woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-compact', release: '3.0', reference: '2.2.20-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-compact is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-compact_2.2.20-5woody5\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-idepci', release: '3.0', reference: '2.2.20-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-idepci is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-idepci_2.2.20-5woody5\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-mac', release: '3.0', reference: '2.2.20-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-mac is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-mac_2.2.20-3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-mvme147', release: '3.0', reference: '2.2.20-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-mvme147 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-mvme147_2.2.20-3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-mvme16x', release: '3.0', reference: '2.2.20-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-mvme16x is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-mvme16x_2.2.20-3\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-pmac', release: '3.0', reference: '2.2.20-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-pmac is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-pmac_2.2.20-3woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-prep', release: '3.0', reference: '2.2.20-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-prep is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-prep_2.2.20-3woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-reiserfs', release: '3.0', reference: '2.2.20-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-reiserfs is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-reiserfs_2.2.20-4woody1\n');
}
if (deb_check(prefix: 'kernel-patch-2.2.20-powerpc', release: '3.0', reference: '2.2.20-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.2.20-powerpc is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.2.20-powerpc_2.2.20-3woody1\n');
}
if (deb_check(prefix: 'kernel-source-2.2.20', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.2.20_2.2.20-5woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
