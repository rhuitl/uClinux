# This script was automatically generated from the dsa-1103
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
    Franz Filz discovered that some socket calls permit causing inconsistent
    reference counts on loadable modules, which allows local users to cause
    a denial of service.
    "Solar Designer" discovered that arithmetic computations in netfilter\'s
    do_replace() function can lead to a buffer overflow and the execution of
    arbitrary code. However, the operation requires CAP_NET_ADMIN privileges,
    which is only an issue in virtualization systems or fine grained access
    control systems.
    "Solar Designer" discovered a race condition in netfilter\'s
    do_add_counters() function, which allows information disclosure of kernel
    memory by exploiting a race condition. Likewise, it requires CAP_NET_ADMIN
    privileges. 
    David Howells discovered that the s390 assembly version of the
    strnlen_user() function incorrectly returns some string size values.
    It was discovered that the ftruncate() function of XFS can expose
    unallocated blocks, which allows information disclosure of previously deleted
    files.
    It was discovered that some NFS file operations on handles mounted with
    O_DIRECT can force the kernel into a crash.
    It was discovered that the code to configure memory policies allows
    tricking the kernel into a crash, thus allowing denial of service.
    It was discovered by Cliff Wickman that perfmon for the IA64
    architecture allows users to trigger a BUG() assert, which allows
    denial of service.
    Intel EM64T systems were discovered to be susceptible to a local
    DoS due to an endless recursive fault related to a bad ELF entry
    address.
    Alan and Gareth discovered that the ia64 platform had an
    incorrectly declared die_if_kernel() function as "does never
    return" which could be exploited by a local attacker resulting in
    a kernel crash.
    The Linux kernel did not properly handle uncanonical return
    addresses on Intel EM64T CPUs, reporting exceptions in the SYSRET
    instead of the next instruction, causing the kernel exception
    handler to run on the user stack with the wrong GS. This may result
    in a DoS due to a local user changing the frames.
    AMD64 machines (and other 7th and 8th generation AuthenticAMD
    processors) were found to be vulnerable to sensitive information
    leakage, due to how they handle saving and restoring the FOP, FIP,
    and FDP x87 registers in FXSAVE/FXRSTOR when an exception is
    pending. This allows a process to determine portions of the state
    of floating point instructions of other processes.
    Marco Ivaldi discovered that there was an unintended information
    disclosure allowing remote attackers to bypass protections against
    Idle Scans (nmap -sI) by abusing the ID field of IP packets and
    bypassing the zero IP ID in DF packet countermeasure. This was a
    result of the ip
[...]

Solution : http://www.debian.org/security/2006/dsa-1103
Risk factor : High';

if (description) {
 script_id(22645);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1103");
 script_cve_id("CVE-2005-3359", "CVE-2006-0038", "CVE-2006-0039", "CVE-2006-0456", "CVE-2006-0554", "CVE-2006-0555", "CVE-2006-0557");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1103] DSA-1103-1 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1103-1 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-build-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3-smp_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4-smp_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc-smp_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.6.8_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-386_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686-smp_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-generic_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7-smp_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-smp_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc32_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64-smp_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-386_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686-smp_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-generic_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7-smp_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley-smp_2.6.8-14sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3-smp_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4-smp_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc-smp_2.6.8-12sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390', release: '3.1', reference: '2.6.8-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390_2.6.8-5sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390-tape', release: '3.1', reference: '2.6.8-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390-tape_2.6.8-5sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390x', release: '3.1', reference: '2.6.8-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390x_2.6.8-5sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-smp_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc32_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64-smp_2.6.8-15sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-amiga_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-atari_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-bvme6000_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-hp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-hp_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mac_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme147_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme16x_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-q40_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-sun3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-sun3_2.6.8-4sarge3\n');
}
if (deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.6.8-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.6.8-s390_2.6.8-5sarge3\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.6.8_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.6.8_2.6.8-16sarge3\n');
}
if (deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.6.8_2.6.8-16sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
