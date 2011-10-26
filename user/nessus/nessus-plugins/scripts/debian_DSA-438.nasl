# This script was automatically generated from the dsa-438
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
version 2.4.18-14.2 of kernel-source, version 2.4.18-14 of alpha
images, version 2.4.18-12.2 of i386 images, version 2.4.18-5woody7
of i386bf images and version 2.4.18-1woody4 of powerpc images.
Other architectures will probably mentioned in a separate advisory or
are not affected (m68k).
For the unstable distribution (sid) this problem is fixed in version
2.4.24-3 for source, i386 and alpha images and version 2.4.22-10 for
powerpc images.
This problem is also fixed in the upstream version of Linux 2.4.25 and
2.6.3.
We recommend that you upgrade your Linux kernel packages immediately.
Vulnerability matrix for CVE-2004-0077


Solution : http://www.debian.org/security/2004/dsa-438
Risk factor : High';

if (description) {
 script_id(15275);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "438");
 script_cve_id("CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA438] DSA-438-1 linux-kernel-2.4.18-alpha+i386+powerpc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-438-1 linux-kernel-2.4.18-alpha+i386+powerpc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.18', release: '3.0', reference: '2.4.18-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.18_2.4.18-14.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18', release: '3.0', reference: '2.4.18-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18_2.4.18-1woody4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-386', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-386_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-586tsc_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-686', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-686_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-686-smp_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-generic', release: '3.0', reference: '2.4.18-14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-generic is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-generic_2.4.18-14\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-k6_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-k7_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-smp', release: '3.0', reference: '2.4.18-14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-smp_2.4.18-14\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-bf2.4', release: '3.0', reference: '2.4.18-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-bf2.4 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-bf2.4_2.4.18-5woody7\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-386', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-386_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-586tsc_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-686', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-686_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-686-smp_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-generic', release: '3.0', reference: '2.4.18-14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-generic is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-generic_2.4.18-14\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-k6_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-k7_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-smp', release: '3.0', reference: '2.4.18-14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-smp_2.4.18-14\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-bf2.4', release: '3.0', reference: '2.4.18-5woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-bf2.4 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-bf2.4_2.4.18-5woody7\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-newpmac', release: '3.0', reference: '2.4.18-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-newpmac is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-newpmac_2.4.18-1woody4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-powerpc is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-powerpc_2.4.18-1woody4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-powerpc-smp', release: '3.0', reference: '2.4.18-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-powerpc-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-powerpc-smp_2.4.18-1woody4\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.18-powerpc is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.18-powerpc_2.4.18-1woody4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-386', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-386_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-586tsc_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-686_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-686-smp_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-k7_2.4.18-12.2\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18', release: '3.0', reference: '2.4.18-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.18_2.4.18-14.2\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18,', release: '3.1', reference: '2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18, is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.4.18,_2.4\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18,', release: '3.0', reference: '2.4.18-14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18, is vulnerable in Debian woody.\nUpgrade to kernel-source-2.4.18,_2.4.18-14\n');
}
if (w) { security_hole(port: 0, data: desc); }
