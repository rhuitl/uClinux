# This script was automatically generated from the dsa-495
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several serious problems have been discovered in the Linux kernel.
This update takes care of Linux 2.4.16 for the ARM architecture.  The
Common Vulnerabilities and Exposures project identifies the following
problems that will be fixed with this update:
    The kernel module loader allows local users to gain root
    privileges by using ptrace to attach to a child process that is
    spawned by the kernel.
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
    Linux.  In a worst case a local attacker could obtain sensitive
    information (such as cryptographic keys in another worst case)
    which would otherwise never hit disk media.  Theodore Ts\'o
    developed a correction for this.
    Andreas Kies discovered a denial of service condition in the Sound
    Blaster driver in Linux.  He also developed a correction for this.
These problems are also fixed by upstream in Linux 2.4.26 and will be
fixed in Linux 2.6.6.
The following security matrix explains which kernel versions for which
architectures are already fixed and which will be removed instead.
We recommend that you upgrade your kernel packages immediately, either
with a Debian provided kernel or with a self compiled one.
Vulnerability matrix for CVE-2004-0109


Solution : http://www.debian.org/security/2004/dsa-495
Risk factor : High';

if (description) {
 script_id(15332);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "495");
 script_cve_id("CVE-2003-0127", "CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
 script_bugtraq_id(10141, 10152, 10152, 7112, 9570, 9691, 9985);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA495] DSA-495-1 linux-kernel-2.4.16-arm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-495-1 linux-kernel-2.4.16-arm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.16', release: '3.0', reference: '2.4.16-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.16 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.16_2.4.16-1woody2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.16', release: '3.0', reference: '20040419')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.16 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.16_20040419\n');
}
if (deb_check(prefix: 'kernel-image-2.4.16-lart', release: '3.0', reference: '20040419')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.16-lart is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.16-lart_20040419\n');
}
if (deb_check(prefix: 'kernel-image-2.4.16-netwinder', release: '3.0', reference: '20040419')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.16-netwinder is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.16-netwinder_20040419\n');
}
if (deb_check(prefix: 'kernel-image-2.4.16-riscpc', release: '3.0', reference: '20040419')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.16-riscpc is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.16-riscpc_20040419\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.16-arm', release: '3.0', reference: '20040419')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.16-arm is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.16-arm_20040419\n');
}
if (deb_check(prefix: 'kernel-source-2.4.16', release: '3.0', reference: '2.4.16-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.16 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.16_2.4.16-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
