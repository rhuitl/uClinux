# This script was automatically generated from the dsa-1183
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in the Linux
kernel which may lead to a denial of service or even the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    A buffer overflow in NFS readlink handling allows a malicious
    remote server to cause a denial of service.
    Diego Calleja Garcia discovered a buffer overflow in the DVD
    handling code that could be exploited by a specially crafted DVD
    USB storage device to execute arbitrary code.
    A bug in the SCSI driver allows a local user to cause a denial of
    service.
    Patrick McHardy discovered a bug in the SNMP NAT helper that
    allows remote attackers to cause a denial of service.
    A race condition in the socket buffer handling allows remote
    attackers to cause a denial of service.
    Wei Wang discovered a bug in the SCTP implementation that allows
    local users to cause a denial of service and possibly gain root
    privileges.
    David Miller reported a problem with the fix for CVE-2006-3745
    that allows local users to crash the system via an SCTP
    socket with a certain SO_LINGER value.
The following matrix explains which kernel version for which
architecture fixes the problem mentioned above:
For the unstable distribution (sid) these problems won\'t be fixed
anymore in the 2.4 kernel series.
We recommend that you upgrade your kernel package and reboot the
machine.  If you have built a custom kernel from the kernel source
package, you will need to rebuild to take advantage of these fixes.


Solution : http://www.debian.org/security/2006/dsa-1183
Risk factor : High';

if (description) {
 script_id(22725);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1183");
 script_cve_id("CVE-2005-4798", "CVE-2006-1528", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-2935", "CVE-2006-3745", "CVE-2006-4535");
 script_bugtraq_id(18081, 18101, 18847, 19666, 20087);
 script_xref(name: "CERT", value: "681569");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1183] DSA-1183-1 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1183-1 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fai-kernels is vulnerable in Debian 3.1.\nUpgrade to fai-kernels_1.9.1sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-2 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-2_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-3_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-apus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-nubus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc-small is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc-small_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.4.27_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-doc-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.4.27-speakup_2.4.27-1.1sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-386_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-586tsc_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-686_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-686-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-generic', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-generic_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-itanium', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-itanium_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-itanium-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-k6_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-k7_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-k7-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-mckinley', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-mckinley_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-mckinley-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-sparc32', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-sparc32_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-sparc32-smp_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-sparc64', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-sparc64_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-2-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-2-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-2-sparc64-smp_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-386_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-586tsc_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-686_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-686-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-generic_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-itanium_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-itanium-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k6_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k7_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k7-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-mckinley_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-mckinley-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc32_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc32-smp_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc64_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc64-smp_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-apus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-nubus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-powerpc_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-speakup_2.4.27-1.1sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-386_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-586tsc_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-686_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-686-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-generic', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-generic_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-itanium', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-itanium_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-itanium-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-k6_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-k7_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-k7-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-mckinley', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-mckinley_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-mckinley-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-s390', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-s390_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-s390-tape', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-s390-tape_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-s390x', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-s390x_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-sparc32', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-sparc32_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-sparc32-smp_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-sparc64', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-sparc64_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-2-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-2-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-2-sparc64-smp_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-386_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-586tsc_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-686_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-686-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-generic_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-itanium_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-itanium-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k6_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k7_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k7-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-mckinley_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-mckinley-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390-tape', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390-tape_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390x', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390x_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc32_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc32-smp_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc64_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc64-smp_2.4.27-9sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-amiga_2.4.27-3sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-apus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-atari_2.4.27-3sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bast is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bast_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bvme6000_2.4.27-3sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-lart is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-lart_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mac_2.4.27-3sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme147_2.4.27-3sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme16x_2.4.27-3sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-netwinder is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-netwinder_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-nubus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc-small is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc-small_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-q40_2.4.27-3sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r3k-kn02 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r3k-kn02_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r4k-ip22 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r4k-ip22_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r4k-kn04 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r4k-kn04_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-cobalt is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-cobalt_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-ip22 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-ip22_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-lasat is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-lasat_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscpc_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscstation is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscstation_2.4.27-2sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-sb1-swarm-bn is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-sb1-swarm-bn_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-speakup_2.4.27-1.1sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-xxs1500 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-xxs1500_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-apus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-nubus_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-powerpc_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-s390', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-s390_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.4.27_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-386', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-2-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-2-386_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-586tsc', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-2-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-2-586tsc_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-2-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-2-686_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-686-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-2-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-2-686-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k6', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-2-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-2-k6_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-2-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-2-k7_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-2-k7-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-2-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-2-k7-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-386_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-586tsc_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-686_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-686-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-k6_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-k7_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-k7-smp_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.4.27_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.4.27_2.4.27-10sarge4\n');
}
if (deb_check(prefix: 'mindi-kernel', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mindi-kernel is vulnerable in Debian 3.1.\nUpgrade to mindi-kernel_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge4.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.1.\nUpgrade to mips-tools_2.4.27-10.sarge4.040815-1\n');
}
if (deb_check(prefix: 'systemimager-boot-i386-standard', release: '3.1', reference: '3.2.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-boot-i386-standard is vulnerable in Debian 3.1.\nUpgrade to systemimager-boot-i386-standard_3.2.3-6sarge3\n');
}
if (deb_check(prefix: 'systemimager-boot-ia64-standard', release: '3.1', reference: '3.2.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-boot-ia64-standard is vulnerable in Debian 3.1.\nUpgrade to systemimager-boot-ia64-standard_3.2.3-6sarge3\n');
}
if (deb_check(prefix: 'systemimager-client', release: '3.1', reference: '3.2.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-client is vulnerable in Debian 3.1.\nUpgrade to systemimager-client_3.2.3-6sarge3\n');
}
if (deb_check(prefix: 'systemimager-common', release: '3.1', reference: '3.2.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-common is vulnerable in Debian 3.1.\nUpgrade to systemimager-common_3.2.3-6sarge3\n');
}
if (deb_check(prefix: 'systemimager-doc', release: '3.1', reference: '3.2.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-doc is vulnerable in Debian 3.1.\nUpgrade to systemimager-doc_3.2.3-6sarge3\n');
}
if (deb_check(prefix: 'systemimager-server', release: '3.1', reference: '3.2.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-server is vulnerable in Debian 3.1.\nUpgrade to systemimager-server_3.2.3-6sarge3\n');
}
if (deb_check(prefix: 'systemimager-server-flamethrowerd', release: '3.1', reference: '3.2.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-server-flamethrowerd is vulnerable in Debian 3.1.\nUpgrade to systemimager-server-flamethrowerd_3.2.3-6sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
