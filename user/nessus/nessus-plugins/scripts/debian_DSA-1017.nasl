# This script was automatically generated from the dsa-1017
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
    Multiple overflows exist in the io_edgeport driver which might be usable
    as a denial of service attack vector.
    Bryan Fulton reported a bounds checking bug in the coda_pioctl function
    which may allow local users to execute arbitrary code or trigger a denial
    of service attack.
    An error in the skb_checksum_help() function from the netfilter framework
    has been discovered that allows the bypass of packet filter rules or
    a denial of service attack.
    Tim Yamin discovered that insufficient input validation in the zisofs driver
    for compressed ISO file systems allows a denial of service attack through
    maliciously crafted ISO images.
    A buffer overflow in the sendmsg() function allows local users to execute
    arbitrary code.
    Herbert Xu discovered that the setsockopt() function was not restricted to
    users/processes with the CAP_NET_ADMIN capability. This allows attackers to
    manipulate IPSEC policies or initiate a denial of service attack. 
    Al Viro discovered a race condition in the /proc handling of network devices.
    A (local) attacker could exploit the stale reference after interface shutdown
    to cause a denial of service or possibly execute code in kernel mode.
    Jan Blunck discovered that repeated failed reads of /proc/scsi/sg/devices
    leak memory, which allows a denial of service attack.
    Tetsuo Handa discovered that the udp_v6_get_port() function from the IPv6 code
    can be forced into an endless loop, which allows a denial of service attack.
    Vasiliy Averin discovered that the reference counters from sockfd_put() and 
    fput() can be forced into overlapping, which allows a denial of service attack
    through a null pointer dereference.
    Eric Dumazet discovered that the set_mempolicy() system call accepts a negative
    value for its first argument, which triggers a BUG() assert. This allows a
    denial of service attack.
    Harald Welte discovered that if a process issues a USB Request Block (URB)
    to a device and terminates before the URB completes, a stale pointer
    would be dereferenced.  This could be used to trigger a denial of service
    attack.
    Pavel Roskin discovered that the driver for Orinoco wireless cards clears
    its buffers insufficiently. This could leak sensitive information into
    user space.
    Robert Derr discovered that the audit subsystem uses an incorrect function to
    free memory, which allows a denial of service attack.
    Rudolf Polzer discovered that the kernel improperly restricts access to the
    KDSKBSENT ioctl, which can possibly lead to privilege escalation.
    Doug Chapman discovered that the mq_open syscall can be tricked into
    decrementing an internal counter twice, which allows a denial of service attack
    through a kernel panic.
    Doug Chapman discovered that pass
[...]

Solution : http://www.debian.org/security/2006/dsa-1017
Risk factor : High';

if (description) {
 script_id(22559);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1017");
 script_cve_id("CVE-2004-1017", "CVE-2005-0124", "CVE-2005-0449", "CVE-2005-2457", "CVE-2005-2490", "CVE-2005-2555", "CVE-2005-2709");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1017] DSA-1017-1 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1017-1 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fai-kernels is vulnerable in Debian 3.1.\nUpgrade to fai-kernels_1.9.1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.4.27-3-386', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.4.27-3-386_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.4.27-3-586tsc', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.4.27-3-586tsc_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.4.27-3-686', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.4.27-3-686_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.4.27-3-686-smp', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.4.27-3-686-smp_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.4.27-3-k6', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.4.27-3-k6_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.4.27-3-k7', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.4.27-3-k7_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.4.27-3-k7-smp', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.4.27-3-k7-smp_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.6.8-3-386', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.6.8-3-386_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.6.8-3-686', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.6.8-3-686_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.6.8-3-686-smp', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.6.8-3-686-smp_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.6.8-3-k7', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.6.8-3-k7_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'hostap-modules-2.6.8-3-k7-smp', release: '3.1', reference: '0.3.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hostap-modules-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to hostap-modules-2.6.8-3-k7-smp_0.3.7-1sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-2', release: '3.1', reference: '2.6.8-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-2 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-2_2.6.8-15sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3-smp_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4-smp_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc-smp_2.6.8-12sarge2\n');
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
if (deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.6.8_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers is vulnerable in Debian 3.1.\nUpgrade to kernel-headers_102sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4_102sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6_102sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-32', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-32_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-32-smp', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-32-smp_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-386', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-386_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-64', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-64_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-64-smp', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-64-smp_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-686', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-686_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-686-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-686-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-amd64-generic', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-amd64-generic_103sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-amd64-k8', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-amd64-k8_103sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-amd64-k8-smp', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-amd64-k8-smp_103sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-em64t-p4', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-em64t-p4_103sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-em64t-p4-smp', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-em64t-p4-smp_103sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-generic', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-generic_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-k7', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-k7_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-k7-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-k7-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-sparc32', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-sparc32_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-sparc64', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-sparc64_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-sparc64-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-sparc64-smp_101sarge1\n');
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
if (deb_check(prefix: 'kernel-headers-2.6.8-12', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-generic_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-k8_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-k8-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-em64t-p4_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-em64t-p4-smp_2.6.8-16sarge2\n');
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
if (deb_check(prefix: 'kernel-headers-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32-smp_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-386_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64-smp_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-generic_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc32_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64-smp_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4-powerpc', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-powerpc_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-powerpc-smp', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-powerpc-smp_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-32', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-32_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-32-smp', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-32-smp_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-386', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-386_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-64', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-64_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-64-smp', release: '3.1', reference: '2.6.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-64-smp_2.6.8-1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-686', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-686_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-686-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-686-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-amd64-generic', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-amd64-generic_103sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-amd64-k8', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-amd64-k8_103sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-amd64-k8-smp', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-amd64-k8-smp_103sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-em64t-p4', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-em64t-p4_103sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-em64t-p4-smp', release: '3.1', reference: '103sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-em64t-p4-smp_103sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-generic', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-generic_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6-k7', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-k7_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-k7-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-k7-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6-power3', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-power3_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-power3-smp', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-power3-smp_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-power4', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-power4_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-power4-smp', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-power4-smp_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-powerpc', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-powerpc_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-powerpc-smp', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-powerpc-smp_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-sparc32', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-sparc32_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-sparc64', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-sparc64_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.6-sparc64-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-sparc64-smp_101sarge1\n');
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
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-generic_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-k8_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-k8-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-em64t-p4_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-em64t-p4-smp_2.6.8-16sarge2\n');
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
if (deb_check(prefix: 'kernel-image-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32-smp_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-386_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64-smp_2.6.8-6sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-generic_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley-smp_2.6.8-14sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3-smp_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4-smp_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc-smp_2.6.8-12sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390', release: '3.1', reference: '2.6.8-5sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390_2.6.8-5sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390-tape', release: '3.1', reference: '2.6.8-5sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390-tape_2.6.8-5sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390x', release: '3.1', reference: '2.6.8-5sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390x_2.6.8-5sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-smp_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc32_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64-smp_2.6.8-15sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-amiga_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-atari_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-bvme6000_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-hp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-hp_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mac_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme147_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme16x_2.6.8-4sarge2\n');
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
if (deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-q40_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-sun3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-sun3_2.6.8-4sarge2\n');
}
if (deb_check(prefix: 'kernel-image-power3', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-power3_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-power3-smp', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-power3-smp_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-power4', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-power4_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-power4-smp', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-power4-smp_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-powerpc', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-powerpc_102sarge1\n');
}
if (deb_check(prefix: 'kernel-image-powerpc-smp', release: '3.1', reference: '102sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-powerpc-smp_102sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.6.8-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.6.8-s390_2.6.8-5sarge2\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.6.8_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.6.8_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.6.8_2.6.8-16sarge2\n');
}
if (deb_check(prefix: 'mol-modules-2.6.8-3-powerpc', release: '3.1', reference: '0.9.70+2.6.8+12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mol-modules-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to mol-modules-2.6.8-3-powerpc_0.9.70+2.6.8+12sarge1\n');
}
if (deb_check(prefix: 'mol-modules-2.6.8-3-powerpc-smp', release: '3.1', reference: '0.9.70+2.6.8+12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mol-modules-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to mol-modules-2.6.8-3-powerpc-smp_0.9.70+2.6.8+12sarge1\n');
}
if (deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-386', release: '3.1', reference: '1.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ndiswrapper-modules-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to ndiswrapper-modules-2.6.8-3-386_1.1-2sarge1\n');
}
if (deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-686', release: '3.1', reference: '1.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ndiswrapper-modules-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to ndiswrapper-modules-2.6.8-3-686_1.1-2sarge1\n');
}
if (deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-686-smp', release: '3.1', reference: '1.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ndiswrapper-modules-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to ndiswrapper-modules-2.6.8-3-686-smp_1.1-2sarge1\n');
}
if (deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-k7', release: '3.1', reference: '1.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ndiswrapper-modules-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to ndiswrapper-modules-2.6.8-3-k7_1.1-2sarge1\n');
}
if (deb_check(prefix: 'ndiswrapper-modules-2.6.8-3-k7-smp', release: '3.1', reference: '1.1-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ndiswrapper-modules-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to ndiswrapper-modules-2.6.8-3-k7-smp_1.1-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
