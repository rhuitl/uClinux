# This script was automatically generated from the dsa-1097
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
    "Solar Designer" discovered that arithmetic computations in netfilter\'s
    do_replace() function can lead to a buffer overflow and the execution of
    arbitrary code. However, the operation requires CAP_NET_ADMIN privileges,
    which is only an issue in virtualization systems or fine grained access
    control systems.
    "Solar Designer" discovered a race condition in netfilter\'s
    do_add_counters() function, which allows information disclosure of
    kernel memory by exploiting a race condition. Like CVE-2006-0038,
    it requires CAP_NET_ADMIN privileges.
    Intel EM64T systems were discovered to be susceptible to a local
    DoS due to an endless recursive fault related to a bad ELF entry
    address.
    Incorrectly declared die_if_kernel() function as "does never
    return" which could be exploited by a local attacker resulting in
    a kernel crash.
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
    result of the ip_push_pending_frames function improperly
    incremented the IP ID field when sending a RST after receiving
    unsolicited TCP SYN-ACK packets.
    Pavel Kankovsky reported the existence of a potential information leak
    resulting from the failure to initialize sin.sin_zero in the IPv4 socket
    code.
    Shaun Tancheff discovered a buffer overflow (boundary condition
    error) in the USB Gadget RNDIS implementation allowing remote
    attackers to cause a DoS. While creating a reply message, the
    driver allocated memory for the reply data, but not for the reply
    structure. The kernel fails to properly bounds-check user-supplied
    data before copying it to an insufficiently sized memory
    buffer. Attackers could crash the system, or possibly execute
    arbitrary machine code.
    Hugh Dickins discovered an issue in the madvise_remove() function wherein
    file and mmap restrictions are not followed, allowing local users to
    bypass IPC permissions and replace portions of readonly tmpfs files with
    zeroes.
    Alexandra Kossovsky reported a NULL pointer dereference condition in
    ip_route_input() that can be triggered by a local user by requesting
    a route for a multicast IP address, resulting in a denial of service
    (panic).
    Vlad
[...]

Solution : http://www.debian.org/security/2006/dsa-1097
Risk factor : High';

if (description) {
 script_id(22639);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1097");
 script_cve_id("CVE-2006-0038", "CVE-2006-0039", "CVE-2006-0741", "CVE-2006-0742", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1343");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1097] DSA-1097-1 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1097-1 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fai-kernels is vulnerable in Debian 3.1.\nUpgrade to fai-kernels_1.9.1sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-3_2.4.27-9sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-apus_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.4.27_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-doc-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.4.27-speakup_2.4.27-1.1sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3_2.4.27-9sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k6_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k7_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-smp_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium-smp_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley-smp_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-386_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-586tsc_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-686_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-686-smp_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-itanium_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k6_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k7_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k7-smp_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-mckinley_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390x', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390x_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc32_2.4.27-9sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc64_2.4.27-9sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-amiga_2.4.27-3sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-apus_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-atari_2.4.27-3sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bast is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bast_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bvme6000_2.4.27-3sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-lart is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-lart_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mac_2.4.27-3sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme147_2.4.27-3sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme16x_2.4.27-3sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-netwinder is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-netwinder_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-q40_2.4.27-3sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge3.040815-+1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-cobalt is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-cobalt_2.4.27-10.sarge3.040815-+1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge3.040815-1+')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-lasat is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-lasat_2.4.27-10.sarge3.040815-1+\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscpc_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscstation is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscstation_2.4.27-2sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge3.04081+5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-sb1-swarm-bn is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-sb1-swarm-bn_2.4.27-10.sarge3.04081+5-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-speakup_2.4.27-1.1sarge2\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-apus_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.4.27_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.4.27_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.4.27_2.4.27-10sarge3\n');
}
if (deb_check(prefix: 'mindi-kernel', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mindi-kernel is vulnerable in Debian 3.1.\nUpgrade to mindi-kernel_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge3.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.1.\nUpgrade to mips-tools_2.4.27-10.sarge3.040815-1\n');
}
if (deb_check(prefix: 'systemimager-boot-i386-standard', release: '3.1', reference: '3.2.3-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-boot-i386-standard is vulnerable in Debian 3.1.\nUpgrade to systemimager-boot-i386-standard_3.2.3-6sarge2\n');
}
if (deb_check(prefix: 'systemimager-boot-ia64-standard', release: '3.1', reference: '3.2.3-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-boot-ia64-standard is vulnerable in Debian 3.1.\nUpgrade to systemimager-boot-ia64-standard_3.2.3-6sarge2\n');
}
if (deb_check(prefix: 'systemimager-client', release: '3.1', reference: '3.2.3-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-client is vulnerable in Debian 3.1.\nUpgrade to systemimager-client_3.2.3-6sarge2\n');
}
if (deb_check(prefix: 'systemimager-common', release: '3.1', reference: '3.2.3-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-common is vulnerable in Debian 3.1.\nUpgrade to systemimager-common_3.2.3-6sarge2\n');
}
if (deb_check(prefix: 'systemimager-doc', release: '3.1', reference: '3.2.3-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-doc is vulnerable in Debian 3.1.\nUpgrade to systemimager-doc_3.2.3-6sarge2\n');
}
if (deb_check(prefix: 'systemimager-server', release: '3.1', reference: '3.2.3-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-server is vulnerable in Debian 3.1.\nUpgrade to systemimager-server_3.2.3-6sarge2\n');
}
if (deb_check(prefix: 'systemimager-server-flamethrowerd', release: '3.1', reference: '3.2.3-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-server-flamethrowerd is vulnerable in Debian 3.1.\nUpgrade to systemimager-server-flamethrowerd_3.2.3-6sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
