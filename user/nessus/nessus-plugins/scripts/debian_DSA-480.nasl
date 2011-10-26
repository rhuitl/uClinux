# This script was automatically generated from the dsa-480
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several serious problems have been discovered in the Linux kernel.
This update takes care of Linux 2.4.17 and 2.4.18 for the hppa
(PA-RISC) architecture.  The Common Vulnerabilities and Exposures
project identifies the following problems that will be fixed with this
update:
    A vulnerability has been discovered in the R128 DRI driver in the Linux
    kernel which could potentially lead an attacker to gain
    unauthorised privileges.  Alan Cox and Thomas Biege developed a
    correction for this.
    Arjan van de Ven discovered a stack-based buffer overflow in the
    ncp_lookup function for ncpfs in the Linux kernel, which could
    lead an attacker to gain unauthorised privileges.  Petr Vandrovec
    developed a correction for this.
    zen-parse discovered a buffer overflow vulnerability in the
    ISO9660 filesystem component of Linux kernel which could be abused
    by an attacker to gain unauthorised root access.  Sebastian
    Krahmer and Ernie Petrides developed a correction for this.
    Solar Designer discovered an information leak in the ext3 code of
    Linux.  In a worst case an attacker could read sensitive data such
    as cryptographic keys which would otherwise never hit disk media.
    Theodore Ts\'o developed a correction for this.
    Andreas Kies discovered a denial of service condition in the Sound
    Blaster driver in Linux.  He also developed a correction for this.
These problems are also fixed by upstream in Linux 2.4.26 and will be
fixed in Linux 2.6.6.
For the stable distribution (woody) these problems have been fixed in
version 32.4 for Linux 2.4.17 and in version 62.3 for Linux 2.4.18.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your kernel packages immediately, either
with a Debian provided kernel or with a self compiled one.
Vulnerability matrix for CVE-2004-0109


Solution : http://www.debian.org/security/2004/dsa-480
Risk factor : High';

if (description) {
 script_id(15317);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "480");
 script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
 script_bugtraq_id(10152);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA480] DSA-480-1 linux-kernel-2.4.17+2.4.18-hppa");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-480-1 linux-kernel-2.4.17+2.4.18-hppa");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-headers-2.4.17-hppa', release: '3.0', reference: '32.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17-hppa is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17-hppa_32.4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-hppa', release: '3.0', reference: '62.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-hppa is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-hppa_62.3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-32', release: '3.0', reference: '32.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-32 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-32_32.4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-32-smp', release: '3.0', reference: '32.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-32-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-32-smp_32.4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-64', release: '3.0', reference: '32.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-64 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-64_32.4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-64-smp', release: '3.0', reference: '32.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-64-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-64-smp_32.4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-32', release: '3.0', reference: '62.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-32 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-32_62.3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-32-smp', release: '3.0', reference: '62.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-32-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-32-smp_62.3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-64', release: '3.0', reference: '62.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-64 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-64_62.3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-64-smp', release: '3.0', reference: '62.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-64-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-64-smp_62.3\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17-hppa', release: '3.0', reference: '32.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17-hppa is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17-hppa_32.4\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18-hppa', release: '3.0', reference: '62.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18-hppa is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.18-hppa_62.3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-hppa', release: '3.0', reference: '32')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-hppa is vulnerable in Debian woody.\nUpgrade to kernel-image-2.4.17-hppa_32\n');
}
if (w) { security_hole(port: 0, data: desc); }
