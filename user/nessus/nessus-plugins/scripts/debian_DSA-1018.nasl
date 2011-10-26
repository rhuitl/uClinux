# This script was automatically generated from the dsa-1018
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

 The original update lacked recompiled ALSA modules against the new kernel
ABI. Furthermore, kernel-latest-2.4-sparc now correctly depends on the
updated packages. For completeness we\'re providing the original problem description:

Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:
    Martin Schwidefsky discovered that the privileged instruction SACF (Set
    Address Space Control Fast) on the S/390 platform is not handled properly, 
    allowing for a local user to gain root privileges.
    A race condition allows for a local user to read the environment variables
    of another process that is still spawning through /proc/.../cmdline.
    A numeric casting discrepancy in sdla_xfer allows local users to read
    portions of kernel memory via a large len argument which is received as an
    int but cast to a short, preventing read loop from filling a buffer.
    An error in the skb_checksum_help() function from the netfilter framework
    has been discovered that allows the bypass of packet filter rules or
    a denial of service attack.
    A vulnerability in the ptrace subsystem of the IA-64 architecture can 
    allow local attackers to overwrite kernel memory and crash the kernel.
    Tim Yamin discovered that insufficient input validation in the compressed
    ISO file system (zisofs) allows a denial of service attack through
    maliciously crafted ISO images.
    Herbert Xu discovered that the setsockopt() function was not restricted to
    users/processes with the CAP_NET_ADMIN capability. This allows attackers to
    manipulate IPSEC policies or initiate a denial of service attack.
    Al Viro discovered a race condition in the /proc handling of network devices.
    A (local) attacker could exploit the stale reference after interface shutdown
    to cause a denial of service or possibly execute code in kernel mode.
    Tetsuo Handa discovered that the udp_v6_get_port() function from the IPv6 code
    can be forced into an endless loop, which allows a denial of service attack.
    Rudolf Polzer discovered that the kernel improperly restricts access to the
    KDSKBSENT ioctl, which can possibly lead to privilege escalation.
    The ptrace code using CLONE_THREAD didn\'t use the thread group ID to
    determine whether the caller is attaching to itself, which allows a denial
    of service attack.
    Yen Zheng discovered that the IPv6 flow label code modified an incorrect variable,
    which could lead to memory corruption and denial of service.
    Ollie Wild discovered a memory leak in the icmp_push_reply() function, which
    allows denial of service through memory consumption.
    Chris Wright discovered that excessive allocation of broken file lock leases
    in the VFS layer can exhaust memory and fill up the system logging, which allows
    denial of service.
    Patrick McHardy discovered a memory leak in the ip6_input_finish() function fro
[...]

Solution : http://www.debian.org/security/2006/dsa-1018
Risk factor : High';

if (description) {
 script_id(22560);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1018");
 script_cve_id("CVE-2004-0887", "CVE-2004-1058", "CVE-2004-2607", "CVE-2005-0449", "CVE-2005-1761", "CVE-2005-2457", "CVE-2005-2555");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1018] DSA-1018-2 kernel-source-2.4.27");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1018-2 kernel-source-2.4.27");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'i2c-2.4.27-3-386', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to i2c-2.4.27-3-386_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'i2c-2.4.27-3-586tsc', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to i2c-2.4.27-3-586tsc_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'i2c-2.4.27-3-686', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to i2c-2.4.27-3-686_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'i2c-2.4.27-3-686-smp', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to i2c-2.4.27-3-686-smp_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'i2c-2.4.27-3-k6', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to i2c-2.4.27-3-k6_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'i2c-2.4.27-3-k7', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to i2c-2.4.27-3-k7_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'i2c-2.4.27-3-k7-smp', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to i2c-2.4.27-3-k7-smp_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'i2c-source', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i2c-source is vulnerable in Debian 3.1.\nUpgrade to i2c-source_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-3_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-apus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-nubus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc-small is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc-small_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-build-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.4.27-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.4.27-powerpc-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-doc-2.4.27', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.4.27_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-doc-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.4.27-speakup_2.4.27-1.1sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-386', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-386_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-586tsc', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-586tsc_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-686', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-686_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-686-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-686-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-generic', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-generic_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-k6', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-k6_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-k7', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-k7_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-k7-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-k7-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-s390', release: '3.1', reference: '2.4.27-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-s390_2.4.27-1sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-sparc32', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-sparc32_42sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-sparc32-smp', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-sparc32-smp_42sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-sparc64', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-sparc64_42sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4-sparc64-smp', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4-sparc64-smp_42sarge1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-386_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-586tsc_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-686_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-686-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-generic_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-itanium_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-itanium-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k6_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k7_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-k7-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-mckinley_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-mckinley-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc32_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc32-smp_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc64_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-3-sparc64-smp_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-apus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-nubus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-powerpc_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.4.27-speakup_2.4.27-1.1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-386', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-386_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-586tsc', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-586tsc_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-686', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-686_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-686-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-686-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-generic', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-generic_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4-itanium-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-itanium-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4-k6', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-k6_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-k7', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-k7_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-k7-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-k7-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-mckinley-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4-s390', release: '3.1', reference: '2.4.27-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-s390_2.4.27-1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-s390x', release: '3.1', reference: '2.4.27-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-s390x_2.4.27-1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-sparc32', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-sparc32_42sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-sparc32-smp', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-sparc32-smp_42sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-sparc64', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-sparc64_42sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4-sparc64-smp', release: '3.1', reference: '42sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4-sparc64-smp_42sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-386_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-586tsc_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-686_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-686-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-generic', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-generic_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-itanium', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-itanium_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-itanium-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-itanium-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k6_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k7_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-k7-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-mckinley', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-mckinley_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-mckinley-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-mckinley-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390-tape', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390-tape_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-s390x', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-s390x_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc32', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc32_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc32-smp', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc32-smp_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc64', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc64_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-3-sparc64-smp', release: '3.1', reference: '2.4.27-9sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-3-sparc64-smp_2.4.27-9sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-amiga', release: '3.1', reference: '2.4.27-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-amiga_2.4.27-3sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-apus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-atari', release: '3.1', reference: '2.4.27-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-atari_2.4.27-3sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bast', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bast is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bast_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-bvme6000', release: '3.1', reference: '2.4.27-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-bvme6000_2.4.27-3sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-lart', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-lart is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-lart_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mac', release: '3.1', reference: '2.4.27-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mac_2.4.27-3sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme147', release: '3.1', reference: '2.4.27-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme147_2.4.27-3sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-mvme16x', release: '3.1', reference: '2.4.27-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-mvme16x_2.4.27-3sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-netwinder', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-netwinder is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-netwinder_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-nubus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc-small', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc-small is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc-small_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-powerpc-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-powerpc-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-q40', release: '3.1', reference: '2.4.27-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-q40_2.4.27-3sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r3k-kn02', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r3k-kn02 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r3k-kn02_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r4k-ip22', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r4k-ip22 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r4k-ip22_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r4k-kn04', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r4k-kn04 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r4k-kn04_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-cobalt', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-cobalt is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-cobalt_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-ip22', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-ip22 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-ip22_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-r5k-lasat', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-r5k-lasat is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-r5k-lasat_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscpc', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscpc_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-riscstation', release: '3.1', reference: '2.4.27-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-riscstation is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-riscstation_2.4.27-2sarge2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-sb1-swarm-bn', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-sb1-swarm-bn is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-sb1-swarm-bn_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-speakup', release: '3.1', reference: '2.4.27-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-speakup is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-speakup_2.4.27-1.1sarge1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.27-xxs1500', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.27-xxs1500 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.27-xxs1500_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4-i2c', release: '3.1', reference: '2.9.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4-i2c is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4-i2c_2.9.1-1sarge1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4-lm-sensors', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4-lm-sensors is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4-lm-sensors_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-apus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-apus is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-apus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-nubus', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-nubus is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-nubus_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.27-powerpc', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.27-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.4.27-powerpc_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.4.27', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.4.27_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4-386', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4-386_101sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4-586tsc', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4-586tsc_101sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4-686', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4-686_101sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4-686-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4-686-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4-k6', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4-k6_101sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4-k7', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4-k7_101sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4-k7-smp', release: '3.1', reference: '101sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4-k7-smp_101sarge1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-386', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-386_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-586tsc', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-586tsc_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-686_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-686-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-686-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k6', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-k6_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-k7_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.27-3-k7-smp', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-pcmcia-modules-2.4.27-3-k7-smp_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-source-2.4.27', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.4.27_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'kernel-tree-2.4.27', release: '3.1', reference: '2.4.27-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.4.27 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.4.27_2.4.27-10sarge2\n');
}
if (deb_check(prefix: 'libsensors-dev', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsensors-dev is vulnerable in Debian 3.1.\nUpgrade to libsensors-dev_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'libsensors3', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsensors3 is vulnerable in Debian 3.1.\nUpgrade to libsensors3_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors is vulnerable in Debian 3.1.\nUpgrade to lm-sensors_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-3-386', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-3-386_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-3-586tsc', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-3-586tsc_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-3-686', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-3-686_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-3-686-smp', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-3-686-smp_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-3-k6', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-3-k6_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-3-k7', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-3-k7_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-2.4.27-3-k7-smp', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-2.4.27-3-k7-smp_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'lm-sensors-source', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lm-sensors-source is vulnerable in Debian 3.1.\nUpgrade to lm-sensors-source_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'mindi-kernel', release: '3.1', reference: '2.4.27-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mindi-kernel is vulnerable in Debian 3.1.\nUpgrade to mindi-kernel_2.4.27-2sarge1\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.1', reference: '2.4.27-10.sarge2.040815-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.1.\nUpgrade to mips-tools_2.4.27-10.sarge2.040815-1\n');
}
if (deb_check(prefix: 'pcmcia-modules-2.4.27-3-386', release: '3.1', reference: '3.2.5+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcmcia-modules-2.4.27-3-386 is vulnerable in Debian 3.1.\nUpgrade to pcmcia-modules-2.4.27-3-386_3.2.5+2sarge1\n');
}
if (deb_check(prefix: 'pcmcia-modules-2.4.27-3-586tsc', release: '3.1', reference: '3.2.5+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcmcia-modules-2.4.27-3-586tsc is vulnerable in Debian 3.1.\nUpgrade to pcmcia-modules-2.4.27-3-586tsc_3.2.5+2sarge1\n');
}
if (deb_check(prefix: 'pcmcia-modules-2.4.27-3-686', release: '3.1', reference: '3.2.5+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcmcia-modules-2.4.27-3-686 is vulnerable in Debian 3.1.\nUpgrade to pcmcia-modules-2.4.27-3-686_3.2.5+2sarge1\n');
}
if (deb_check(prefix: 'pcmcia-modules-2.4.27-3-686-smp', release: '3.1', reference: '3.2.5+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcmcia-modules-2.4.27-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to pcmcia-modules-2.4.27-3-686-smp_3.2.5+2sarge1\n');
}
if (deb_check(prefix: 'pcmcia-modules-2.4.27-3-k6', release: '3.1', reference: '3.2.5+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcmcia-modules-2.4.27-3-k6 is vulnerable in Debian 3.1.\nUpgrade to pcmcia-modules-2.4.27-3-k6_3.2.5+2sarge1\n');
}
if (deb_check(prefix: 'pcmcia-modules-2.4.27-3-k7', release: '3.1', reference: '3.2.5+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcmcia-modules-2.4.27-3-k7 is vulnerable in Debian 3.1.\nUpgrade to pcmcia-modules-2.4.27-3-k7_3.2.5+2sarge1\n');
}
if (deb_check(prefix: 'pcmcia-modules-2.4.27-3-k7-smp', release: '3.1', reference: '3.2.5+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pcmcia-modules-2.4.27-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to pcmcia-modules-2.4.27-3-k7-smp_3.2.5+2sarge1\n');
}
if (deb_check(prefix: 'sensord', release: '3.1', reference: '2.9.1-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sensord is vulnerable in Debian 3.1.\nUpgrade to sensord_2.9.1-1sarge3\n');
}
if (deb_check(prefix: 'systemimager-boot-i386-standard', release: '3.1', reference: '3.2.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-boot-i386-standard is vulnerable in Debian 3.1.\nUpgrade to systemimager-boot-i386-standard_3.2.3-6sarge1\n');
}
if (deb_check(prefix: 'systemimager-boot-ia64-standard', release: '3.1', reference: '3.2.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-boot-ia64-standard is vulnerable in Debian 3.1.\nUpgrade to systemimager-boot-ia64-standard_3.2.3-6sarge1\n');
}
if (deb_check(prefix: 'systemimager-client', release: '3.1', reference: '3.2.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-client is vulnerable in Debian 3.1.\nUpgrade to systemimager-client_3.2.3-6sarge1\n');
}
if (deb_check(prefix: 'systemimager-common', release: '3.1', reference: '3.2.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-common is vulnerable in Debian 3.1.\nUpgrade to systemimager-common_3.2.3-6sarge1\n');
}
if (deb_check(prefix: 'systemimager-doc', release: '3.1', reference: '3.2.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-doc is vulnerable in Debian 3.1.\nUpgrade to systemimager-doc_3.2.3-6sarge1\n');
}
if (deb_check(prefix: 'systemimager-server', release: '3.1', reference: '3.2.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-server is vulnerable in Debian 3.1.\nUpgrade to systemimager-server_3.2.3-6sarge1\n');
}
if (deb_check(prefix: 'systemimager-server-flamethrowerd', release: '3.1', reference: '3.2.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package systemimager-server-flamethrowerd is vulnerable in Debian 3.1.\nUpgrade to systemimager-server-flamethrowerd_3.2.3-6sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
