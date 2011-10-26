# This script was automatically generated from the dsa-423
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The IA-64 maintainers fixed several security related bugs in the Linux
kernel 2.4.17 used for the IA-64 architecture, mostly by backporting
fixes from 2.4.18.  The corrections are listed below with the
identification from the Common Vulnerabilities and Exposures (CVE)
project:
    Multiple ethernet network interface card (NIC) device drivers do
    not pad frames with null bytes, which allows remote attackers to
    obtain information from previous packets or kernel memory by using
    malformed packets, as demonstrated by Etherleak.
    Linux kernel 2.4.10 through 2.4.21-pre4 does not properly handle
    the O_DIRECT feature, which allows local attackers with write
    privileges to read portions of previously deleted files, or cause
    file system corruption.
    The kernel module loader in Linux kernel 2.2.x before 2.2.25, and
    2.4.x before 2.4.21, allows local users to gain root privileges
    by using ptrace to attach to a child process which is spawned by
    the kernel.
    The virtual file /proc/tty/driver/serial in Linux 2.4.x reveals
    the exact number of characters used in serial links, which could
    allow local users to obtain potentially sensitive information such
    as the length of passwords.
    A race condition in the way env_start and env_end pointers are
    initialized in the execve system call and used in fs/proc/base.c
    on Linux 2.4 allows local users to cause a denial of service
    (crash).
    The execve system call in Linux 2.4.x records the file descriptor
    of the executable process in the file table of the calling
    process, which allows local users to gain read access to
    restricted file descriptors.
    The /proc filesystem in Linux allows local users to obtain
    sensitive information by opening various entries in /proc/self
    before executing a setuid program, which causes the program to
    fail to change the ownership and permissions of those entries.
    The STP protocol, as enabled in Linux 2.4.x, does not provide
    sufficient security by design, which allows attackers to modify
    the bridge topology.
    The STP protocol implementation in Linux 2.4.x does not properly
    verify certain lengths, which could allow attackers to cause a
    denial of service.
    Linux 2.4.x allows remote attackers to spoof the bridge Forwarding
    table via forged packets whose source addresses are the same as
    the target.
    An integer overflow in brk system call (do_brk function) for Linux
    kernel 2.4.22 and earlier allows local users to gain root
    privileges.
    The mremap system call (do_mremap) in Linux kernel 2.4 and 2.6
    does not properly perform boundary checks, which allows local
    users to cause a denial of service and possibly gain privileges by
    causing a remapping of a virtual memory area (VMA) to create a
    zero length VMA.
For the stable distribution (woody) this problem has been fixed in
version kernel-image-2.4.17-ia64 for the ia64 architecture.  Other
architectures are already or will be fixed separately.
For the unstable distribution (sid) this problem will b
[...]

Solution : http://www.debian.org/security/2004/dsa-423
Risk factor : High';

if (description) {
 script_id(15260);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "423");
 script_cve_id("CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0461", "CVE-2003-0462", "CVE-2003-0476", "CVE-2003-0501", "CVE-2003-0550");
 script_bugtraq_id(10330, 6535, 6763, 7112, 8002, 8042, 8233);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA423] DSA-423-1 linux-kernel-2.4.17-ia64");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-423-1 linux-kernel-2.4.17-ia64");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-headers-2.4.17-ia64', release: '3.0', reference: '011226.15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17-ia64 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17-ia64_011226.15\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-itanium', release: '3.0', reference: '011226.15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-itanium is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-itanium_011226.15\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-itanium-smp', release: '3.0', reference: '011226.15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-itanium-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-itanium-smp_011226.15\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-mckinley', release: '3.0', reference: '011226.15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-mckinley is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-mckinley_011226.15\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-mckinley-smp', release: '3.0', reference: '011226.15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-mckinley-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-mckinley-smp_011226.15\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17-ia64', release: '3.0', reference: '011226.15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17-ia64 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17-ia64_011226.15\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-ia64', release: '3.0', reference: 'kernel-image-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-ia64 is vulnerable in Debian woody.\nUpgrade to kernel-image-2.4.17-ia64_kernel-image-2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
