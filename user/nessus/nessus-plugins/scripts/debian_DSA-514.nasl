# This script was automatically generated from the dsa-514
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Starzetz and Wojciech Purczynski of isec.pl discovered a critical
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
For the stable distribution (woody) these problems have been fixed in
version 9woody1 of Linux 2.2 kernel images for the sparc architecture
and in version 2.2.20-5woody3 of Linux 2.2.20 source.
For the unstable distribution (sid) these problems have been fixed in
version 9.1 of Linux 2.2 kernel images for the sparc architecture.
This problem has been fixed for other architectures already.
We recommend that you upgrade your Linux kernel package.


Solution : http://www.debian.org/security/2004/dsa-514
Risk factor : High';

if (description) {
 script_id(15351);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "514");
 script_cve_id("CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA514] DSA-514-1 kernel-image-sparc-2.2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-514-1 kernel-image-sparc-2.2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.2.20', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.2.20_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.20-sparc', release: '3.0', reference: '9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.20-sparc is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.2.20-sparc_9woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-sun4cdm', release: '3.0', reference: '9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-sun4cdm is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-sun4cdm_9woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-sun4dm-smp', release: '3.0', reference: '9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-sun4dm-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-sun4dm-smp_9woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-sun4u', release: '3.0', reference: '9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-sun4u is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-sun4u_9woody1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.20-sun4u-smp', release: '3.0', reference: '9woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.20-sun4u-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.2.20-sun4u-smp_9woody1\n');
}
if (deb_check(prefix: 'kernel-source-2.2.20', release: '3.0', reference: '2.2.20-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.2.20 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.2.20_2.2.20-5woody3\n');
}
if (deb_check(prefix: 'kernel-source-2.2.20,', release: '3.1', reference: '9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.2.20, is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.2.20,_9\n');
}
if (w) { security_hole(port: 0, data: desc); }
