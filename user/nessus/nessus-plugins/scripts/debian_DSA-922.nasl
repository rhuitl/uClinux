# This script was automatically generated from the dsa-922
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
    A race condition in the sysfs filesystem allows local users to
    read kernel memory and cause a denial of service (crash).
    Alexander Nyberg discovered that the ptrace() system call does not
    properly verify addresses on the amd64 architecture which can be
    exploited by a local attacker to crash the kernel.
    A problem in the offset handling in the xattr file system code for
    ext3 has been discovered that may allow users on 64-bit systems
    that have access to an ext3 filesystem with extended attributes to
    cause the kernel to crash.
    Chris Wright discovered that the mmap() function could create
    illegal memory maps that could be exploited by a local user to
    crash the kernel or potentially execute arbitrary code.
    A vulnerability on the IA-64 architecture can lead local attackers
    to overwrite kernel memory and crash the kernel.
    A vulnerability has been discovered in the ptrace() system call on
    the amd64 architecture that allows a local attacker to cause the
    kernel to crash.
    A buffer overflow in the ptrace system call for 64-bit
    architectures allows local users to write bytes into arbitrary
    kernel memory.
    Zou Nan Hai has discovered that a local user could cause the
    kernel to hang on the amd64 architecture after invoking syscall()
    with specially crafted arguments.
    A vulnerability has been discovered in the stack segment fault
    handler that could allow a local attacker to cause a stack exception
    that will lead the kernel to crash under certain circumstances.
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
    Peter Sandstrom noticed that snmpwalk from a remote host could
    cause a denial of service (kernel oops from null dereference) via
    certain UDP packets that lead to a function call with the wrong
    argument.
    Andreas Gruenbacher discovered a bug in the ext2 and ext3 file
    systems.  When data areas are to be shared among two inodes not
    all information were compared for equality, which could expose
    wrong ACLs for files.
    Chad Walstrom discovered that the ipt_recent kernel module on
    64-bit processors such as AMD64 allows remote attackers to cause a
    denial of service (kernel panic) via certain attacks such as SSH
    brute force.
    The mprotect code on Itanium IA-64 Montecito processors does not
    proper
[...]

Solution : http://www.debian.org/security/2005/dsa-922
Risk factor : High';

if (description) {
 script_id(22788);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "922");
 script_cve_id("CVE-2004-2302", "CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1265", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1763");
 script_bugtraq_id(14477, 15527, 15528, 15533);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA922] DSA-922-1 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-922-1 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-build-2.6.8-2', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-2 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-2_2.6.8-15sarge1\n');
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
if (deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.6.8_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium-smp_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley-smp_2.6.8-14sarge1\n');
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
if (deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium-smp_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley_2.6.8-14sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley-smp_2.6.8-14sarge1\n');
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
if (deb_check(prefix: 'kernel-image-2.6.8-2-s390', release: '3.1', reference: '2.6.8-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-s390_2.6.8-5sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-s390-tape', release: '3.1', reference: '2.6.8-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-s390-tape_2.6.8-5sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-2-s390x', release: '3.1', reference: '2.6.8-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-2-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-2-s390x_2.6.8-5sarge1\n');
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
if (deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-amiga_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-atari_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-bvme6000_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-hp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-hp_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mac_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme147_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme16x_2.6.8-4sarge1\n');
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
if (deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-q40_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-sun3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-sun3_2.6.8-4sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.6.8-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.6.8-s390_2.6.8-5sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.6.8_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.6.8_2.6.8-16sarge1\n');
}
if (deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.6.8_2.6.8-16sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
