# This script was automatically generated from the dsa-1184
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
This advisory covers the S/390 components of the recent security
update for the Linux 2.6.8 kernel that were missing due to technical
problems. For reference, please see the text of the original advisory.
Several security related problems have been discovered in the Linux
kernel which may lead to a denial of service or even the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Toshihiro Iwamoto discovered a memory leak in the handling of
    direct I/O writes that allows local users to cause a denial of
    service.
    A buffer overflow in NFS readlink handling allows a malicious
    remote server to cause a denial of service.
    Stephen Smalley discovered a bug in the SELinux ptrace handling
    that allows local users with ptrace permissions to change the
    tracer SID to the SID of another process.
    Pavel Kankovsky discovered an information leak in the getsockopt
    system call which can be exploited by a local program to leak
    potentially sensitive memory to userspace.
    Douglas Gilbert reported a bug in the sg driver that allows local
    users to cause a denial of service by performing direct I/O
    transfers from the sg driver to memory mapped I/O space.
    Mattia Belletti noticed that certain debugging code left in the
    process management code could be exploited by a local attacker to
    cause a denial of service.
    Kostik Belousov discovered a missing LSM file_permission check in
    the readv and writev functions which might allow attackers to
    bypass intended access restrictions.
    Patrick McHardy discovered a bug in the SNMP NAT helper that
    allows remote attackers to cause a denial of service.
    A race condition in the socket buffer handling allows remote
    attackers to cause a denial of service.
    Diego Calleja Garcia discovered a buffer overflow in the DVD
    handling code that could be exploited by a specially crafted DVD
    USB storage device to execute arbitrary code.
    A bug in the serial USB driver has been discovered that could be
    exploited by a custom made USB serial adapter to consume arbitrary
    amounts of memory.
    James McKenzie discovered a denial of service vulnerability in the
    NFS driver.  When exporting an ext3 file system over NFS, a remote
    attacker could exploit this to trigger a file system panic by
    sending a specially crafted UDP packet.
    Wei Wang discovered a bug in the SCTP implementation that allows
    local users to cause a denial of service and possibly gain root
    privileges.
    Olof Johansson discovered that the kernel does not disable the HID0
    bit on PowerPC 970 processors which could be exploited by a local
    attacker to cause a denial of service.
    A bug in the Universal Disk Format (UDF) filesystem driver could
    be exploited by a local user to cause a denial of service.
    David Miller reported a problem with the fix for CVE-2006-3745
    that allows local users to crash the system via an SCTP
    socket with a certain SO_LINGER value.
The following matrix 
[...]

Solution : http://www.debian.org/security/2006/dsa-1184
Risk factor : High';

if (description) {
 script_id(22726);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1184");
 script_cve_id("CVE-2004-2660", "CVE-2005-4798", "CVE-2006-1052", "CVE-2006-1343", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856");
 script_bugtraq_id(17203, 17830, 18081, 18099, 18101, 18105, 18847);
 script_xref(name: "CERT", value: "681569");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1184] DSA-1184-2 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1184-2 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-source-2.6.8', release: '', reference: '2.6.18-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.6.8 is vulnerable in Debian .\nUpgrade to kernel-source-2.6.8_2.6.18-1\n');
}
if (deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fai-kernels is vulnerable in Debian 3.1.\nUpgrade to fai-kernels_1.9.1sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-2', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-2 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-2_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3-smp_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4-smp_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc-smp_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-power3', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-power3_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-power3-smp', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-power3-smp_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-power4', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-power4_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-power4-smp', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-power4-smp_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-powerpc', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-powerpc_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-powerpc-smp_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.6.8_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-11', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-11 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-11_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-generic', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-11-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-11-amd64-generic_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-k8', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-11-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-11-amd64-k8_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-11-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-11-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-11-amd64-k8-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-11-em64t-p4', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-11-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-11-em64t-p4_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-11-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-11-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-11-em64t-p4-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-generic_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-k8_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-k8-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-em64t-p4_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-em64t-p4-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-32', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-32_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-32-smp', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-32-smp_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-386', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-386_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-64', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-64_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-64-smp', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-64-smp_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-686', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-686_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-686-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-686-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-generic', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-generic_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-itanium', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-itanium_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-itanium-smp_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-k7', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-k7_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-k7-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-k7-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-mckinley', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-mckinley_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-mckinley-smp_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-sparc32', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-sparc32_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-sparc64', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-sparc64_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-2-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-2-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-2-sparc64-smp_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32-smp_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-386_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64-smp_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-generic_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc32_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64-smp_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-11-amd64-generic', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-11-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-11-amd64-generic_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-11-amd64-k8', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-11-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-11-amd64-k8_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-11-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-11-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-11-amd64-k8-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-11-em64t-p4', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-11-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-11-em64t-p4_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-11-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-11-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-11-em64t-p4-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-generic_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-k8_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-k8-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-em64t-p4_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-em64t-p4-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-32', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-32_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-32-smp', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-32-smp_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-386', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-386_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-64', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-64_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-64-smp', release: '3.1', reference: '2.6.8-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-64-smp_2.6.8-6sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-686', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-686_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-686-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-686-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-generic', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-generic_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-itanium', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-itanium_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-itanium-smp_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-k7', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-k7_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-k7-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-k7-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-mckinley', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-mckinley_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-mckinley-smp_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-smp', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-smp_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-sparc32', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-sparc32_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-sparc64', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-sparc64_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-sparc64-smp_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32-smp_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-386_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64-smp_2.6.8-6sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-generic_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley-smp_2.6.8-14sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3-smp_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4-smp_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc-smp_2.6.8-12sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390', release: '3.1', reference: '2.6.8-5sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390_2.6.8-5sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390-tape', release: '3.1', reference: '2.6.8-5sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390-tape_2.6.8-5sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390x', release: '3.1', reference: '2.6.8-5sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390x_2.6.8-5sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-smp_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc32_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64-smp_2.6.8-15sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-amiga_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-atari_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-bvme6000_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-hp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-hp_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mac_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme147_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme16x_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-power3', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-power3_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-power3-smp', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-power3-smp_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-power4', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-power4_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-power4-smp', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-power4-smp_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-powerpc', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-powerpc_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-powerpc-smp_2.6.8-12sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-q40_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-sun3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-sun3_2.6.8-4sarge5\n');
}
if (deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.6.8-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.6.8-s390_2.6.8-5sarge5\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.6.8_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.6.8_2.6.8-16sarge5\n');
}
if (deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.6.8_2.6.8-16sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
