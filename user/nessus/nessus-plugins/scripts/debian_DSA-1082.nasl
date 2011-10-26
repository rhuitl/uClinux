# This script was automatically generated from the dsa-1082
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
     A local denial of service vulnerability in do_fork() has been found.
     A local denial of service vulnerability in proc memory handling has
     been found.
     A buffer overflow in the panic handling code has been found.
     A local denial of service vulnerability through a null pointer
     dereference in the IA64 process handling code has been found.
     A local denial of service vulnerability through an infinite loop in
     the signal handler code has been found.
     An information leak in the context switch code has been found on
     the IA64 architecture.
     Unsafe use of copy_to_user in USB drivers may disclose sensitive
     information.
     A race condition in the i386 page fault handler may allow privilege
     escalation.
     Multiple vulnerabilities in the SMB filesystem code may allow denial
     of service or information disclosure.
     An information leak discovered in the SMB filesystem code.
     A local denial of service vulnerability has been found in the SCM layer.
     An integer overflow in the terminal code may allow a local denial of
     service vulnerability.
     A local privilege escalation in the MIPS assembly code has been found.
     A memory leak in the ip_options_get() function may lead to denial of
     service.
     Multiple overflows exist in the io_edgeport driver which might be usable
     as a denial of service attack vector.
     Bryan Fulton reported a bounds checking bug in the coda_pioctl function
     which may allow local users to execute arbitrary code or trigger a denial
     of service attack.
     Inproper initialization of the RTC may disclose information.
     Insufficient input sanitising in the load_elf_binary() function may
     lead to privilege escalation.
     Incorrect error handling in the binfmt_elf loader may lead to privilege
     escalation.
     A buffer overflow in the binfmt_elf loader may lead to privilege
     escalation or denial of service.
     The open_exec function may disclose information.
     The binfmt code is vulnerable to denial of service through malformed
     a.out binaries.
     A denial of service vulnerability in the ELF loader has been found.
     A programming error in the unix_dgram_recvmsg() function may lead to
     privilege escalation.
     The ELF loader is vulnerable to denial of service through malformed
     binaries.
     Crafted ELF binaries may lead to privilege escalation, due to 
     insufficient checking of overlapping memory regions.
     A race condition in the load_elf_library() and binfmt_aout() functions
     may allow privilege escalation.
     An integer overflow in the Moxa driver may lead to privilege escalation.
     A remote denial of service vulnerability has been found in the PPP
     driver.
     An IA64 specific local denial of service vulnerability has been found
     in the
[...]

Solution : http://www.debian.org/security/2006/dsa-1082
Risk factor : High';

if (description) {
 script_id(22624);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1082");
 script_cve_id("CVE-2003-0984", "CVE-2004-0138", "CVE-2004-0394", "CVE-2004-0427", "CVE-2004-0447", "CVE-2004-0554", "CVE-2004-0565");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1082] DSA-1082-1 kernel-source-2.4.17");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1082-1 kernel-source-2.4.17");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.17', release: '3.0', reference: '2.4.17-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.17_2.4.17-1woody4\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-0.020226.2.woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17_2.4.17-0.020226.2.woody7\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.17-apus', release: '3.0', reference: '2.4.17-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17-apus_2.4.17-6\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.17-hppa', release: '3.0', reference: '32.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17-hppa is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17-hppa_32.5\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.17-ia64', release: '3.0', reference: '011226.18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17-ia64 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17-ia64_011226.18\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-32', release: '3.0', reference: '32.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-32 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-32_32.5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-32-smp', release: '3.0', reference: '32.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-32-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-32-smp_32.5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-64', release: '3.0', reference: '32.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-64 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-64_32.5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-64-smp', release: '3.0', reference: '32.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-64-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-64-smp_32.5\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-apus', release: '3.0', reference: '2.4.17-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-apus_2.4.17-6\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-itanium', release: '3.0', reference: '011226.18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-itanium is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-itanium_011226.18\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-itanium-smp', release: '3.0', reference: '011226.18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-itanium-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-itanium-smp_011226.18\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-mckinley', release: '3.0', reference: '011226.18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-mckinley is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-mckinley_011226.18\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-mckinley-smp', release: '3.0', reference: '011226.18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-mckinley-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-mckinley-smp_011226.18\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r3k-kn02', release: '3.0', reference: '2.4.17-0.020226.2.woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r3k-kn02 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r3k-kn02_2.4.17-0.020226.2.woody7\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-ip22_2.4.17-0.020226.2.woody7\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-kn04', release: '3.0', reference: '2.4.17-0.020226.2.woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-kn04 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-kn04_2.4.17-0.020226.2.woody7\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r5k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r5k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r5k-ip22_2.4.17-0.020226.2.woody7\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-s390', release: '3.0', reference: '2.4.17-2.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-s390 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-s390_2.4.17-2.woody.5\n');
}
if (deb_check(prefix: 'kernel-image-apus', release: '3.0', reference: '2.4.17-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-image-apus_2.4.17-6\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-apus', release: '3.0', reference: '2.4.17-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-apus_2.4.17-6\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2.woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-mips_2.4.17-0.020226.2.woody7\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-s390', release: '3.0', reference: '0.0.20020816-0.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-s390 is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-s390_0.0.20020816-0.woody.4\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17', release: '3.0', reference: '2.4.17-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17_2.4.17-1woody4\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17-hppa', release: '3.0', reference: '32.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17-hppa is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17-hppa_32.5\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17-ia64', release: '3.0', reference: '011226.18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17-ia64 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17-ia64_011226.18\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.0', reference: '2.4.17-0.020226.2.woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.0.\nUpgrade to mips-tools_2.4.17-0.020226.2.woody7\n');
}
if (deb_check(prefix: 'mkcramfs', release: '3.0', reference: '2.4.17-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mkcramfs is vulnerable in Debian 3.0.\nUpgrade to mkcramfs_2.4.17-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
