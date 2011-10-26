# This script was automatically generated from the dsa-921
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Alexander Nyberg discovered that the ptrace() system call does not
    properly verify addresses on the amd64 architecture which can be
    exploited by a local attacker to crash the kernel.
    A problem in the offset handling in the xattr file system code for
    ext3 has been discovered that may allow users on 64-bit systems
    that have access to an ext3 filesystem with extended attributes to
    cause the kernel to crash.
    A vulnerability has been discovered in the ptrace() system call on
    the amd64 architecture that allows a local attacker to cause the
    kernel to crash.
    A vulnerability has been discovered in the stack segment fault
    handler that could allow a local attacker to cause a stack exception
    that will lead the kernel to crash under certain circumstances.
    Ilja van Sprundel discovered a race condition in the IA32 (x86)
    compatibility execve() systemcall for amd64 and IA64 that allows
    local attackers to cause the kernel to panic and possibly execute
    arbitrary code.
    Balazs Scheidler discovered that a local attacker could call
    setsockopt() with an invalid xfrm_user policy message which would
    cause the kernel to write beyond the boundaries of an array and
    crash.
    Vladimir Volovich discovered a bug in the zlib routines which are
    also present in the Linux kernel and allows remote attackers to
    crash the kernel.
    Another vulnerability has been discovered in the zlib routines
    which are also present in the Linux kernel and allows remote
    attackers to crash the kernel.
    A null pointer dereference in ptrace when tracing a 64-bit
    executable can cause the kernel to crash.
    Andreas Gruenbacher discovered a bug in the ext2 and ext3 file
    systems.  When data areas are to be shared among two inodes not
    all information were compared for equality, which could expose
    wrong ACLs for files.
    Chad Walstrom discovered that the ipt_recent kernel module to stop
    SSH bruteforce attacks could cause the kernel to crash on 64-bit
    architectures.
    An error in the NAT code allows remote attackers to cause a denial
    of service (memory corruption) by causing two packets for the same
    protocol to be NATed at the same time, which leads to memory
    corruption.
The following matrix explains which kernel version for which architecture
fix the problems mentioned above:
We recommend that you upgrade your kernel package immediately and
reboot the machine.


Solution : http://www.debian.org/security/2005/dsa-921
Risk factor : High';

if (description) {
 script_id(22787);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "921");
 script_cve_id("CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1762", "CVE-2005-1767", "CVE-2005-1768", "CVE-2005-2456", "CVE-2005-2458");
 script_bugtraq_id(14477);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA921] DSA-921-1 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-921-1 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-2', release: '3.1', reference: '2.4.27-9sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-2 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-2_2.4.27-9sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-apus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-nubus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc-small is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc-small_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.4.27_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27_2.4.27-10.sarge1.040815-1\n');
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
if (deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-apus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-nubus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-powerpc_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley-smp_2.4.27-10sarge1\n');
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
if (deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-amiga_2.4.27-3sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-apus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-atari_2.4.27-3sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bast is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bast_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bvme6000_2.4.27-3sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-lart is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-lart_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mac_2.4.27-3sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme147_2.4.27-3sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme16x_2.4.27-3sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-netwinder is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-netwinder_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-nubus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc-small is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc-small_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc-smp_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-q40_2.4.27-3sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r3k-kn02 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r3k-kn02_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r4k-ip22 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r4k-ip22_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r4k-kn04 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r4k-kn04_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-cobalt is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-cobalt_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-ip22 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-ip22_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-lasat is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-lasat_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscpc_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscstation is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscstation_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-sb1-swarm-bn is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-sb1-swarm-bn_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-xxs1500 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-xxs1500_2.4.27-10.sarge1.040815-1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-apus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-arm', release: '3.1', reference: '2.4.27-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-arm is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-arm_2.4.27-1sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-nubus_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-powerpc_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.4.27_2.4.27-10sarge1\n');
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
if (deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.4.27_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.4.27_2.4.27-10sarge1\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge1.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.1.\nUpgrade to mips-tools_2.4.27-10.sarge1.040815-1\n');
}
if (w) { security_hole(port: 0, data: desc); }
