# This script was automatically generated from the dsa-047
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The kernels used in Debian GNU/Linux 2.2 have been found to have 
multiple security problems. This is a list of problems based 
on the 2.2.19 release notes as found on 
http://www.linux.org.uk/:


binfmt_misc used user pages directly
the CPIA driver had an off-by-one error in the buffer code which made
  it possible for users to write into kernel memory
the CPUID and MSR drivers had a problem in the module unloading code
  which could cause a system crash if they were set to automatically load
  and unload (please note that Debian does not automatically unload kernel
  modules)
There was a possible hang in the classifier code
The getsockopt and setsockopt system calls did not handle sign bits
  correctly which made a local DoS and other attacks possible
The sysctl system call did not handle sign bits correctly which allowed
  a user to write in kernel memory
ptrace/exec races that could give a local user extra privileges
possible abuse of a boundary case in the sockfilter code
SYSV shared memory code could overwrite recently freed memory which might
  cause problems
The packet length checks in the masquerading code were a bit lax
  (probably not exploitable)
Some x86 assembly bugs caused the wrong number of bytes to be copied.
A local user could deadlock the kernel due to bugs in the UDP port
  allocation.


All these problems are fixed in the 2.2.19 kernel, and it is highly
recommend that you upgrade machines to this kernel.

Please note that kernel upgrades are not done automatically. You will
have to explicitly tell the packaging system to install the right kernel
for your system.




Solution : http://www.debian.org/security/2001/dsa-047
Risk factor : High';

if (description) {
 script_id(14884);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "047");
 script_cve_id("CVE-2001-1390", "CVE-2001-1391", "CVE-2001-1392", "CVE-2001-1393", "CVE-2001-1394", "CVE-2001-1395", "CVE-2001-1396");
 script_bugtraq_id(2529);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA047] DSA-047-1 kernel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-047-1 kernel");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.2.19', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.2.19 is vulnerable in Debian 2.2.\nUpgrade to kernel-doc-2.2.19_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.19', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.19 is vulnerable in Debian 2.2.\nUpgrade to kernel-headers-2.2.19_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.19-compact', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.19-compact is vulnerable in Debian 2.2.\nUpgrade to kernel-headers-2.2.19-compact_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.19-ide', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.19-ide is vulnerable in Debian 2.2.\nUpgrade to kernel-headers-2.2.19-ide_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.19-idepci', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.19-idepci is vulnerable in Debian 2.2.\nUpgrade to kernel-headers-2.2.19-idepci_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-headers-2.2.19-sparc', release: '2.2', reference: '6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.2.19-sparc is vulnerable in Debian 2.2.\nUpgrade to kernel-headers-2.2.19-sparc_6\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19 is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-amiga', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-amiga is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-amiga_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-atari', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-atari is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-atari_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-bvme6000', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-bvme6000 is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-bvme6000_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-chrp', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-chrp is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-chrp_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-compact', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-compact is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-compact_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-generic', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-generic is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-generic_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-ide', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-ide is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-ide_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-idepci', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-idepci is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-idepci_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-jensen', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-jensen is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-jensen_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-mac', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-mac is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-mac_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-mvme147', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-mvme147 is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-mvme147_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-mvme16x', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-mvme16x is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-mvme16x_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-nautilus', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-nautilus is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-nautilus_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-pmac', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-pmac is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-pmac_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-prep', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-prep is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-prep_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-riscpc', release: '2.2', reference: '20010414')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-riscpc is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-riscpc_20010414\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-smp', release: '2.2', reference: '2.2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-smp is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-smp_2.2.19-1\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-sun4cdm', release: '2.2', reference: '6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-sun4cdm is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-sun4cdm_6\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-sun4dm-pci', release: '2.2', reference: '6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-sun4dm-pci is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-sun4dm-pci_6\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-sun4dm-smp', release: '2.2', reference: '6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-sun4dm-smp is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-sun4dm-smp_6\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-sun4u', release: '2.2', reference: '6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-sun4u is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-sun4u_6\n');
}
if (deb_check(prefix: 'kernel-image-2.2.19-sun4u-smp', release: '2.2', reference: '6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.2.19-sun4u-smp is vulnerable in Debian 2.2.\nUpgrade to kernel-image-2.2.19-sun4u-smp_6\n');
}
if (deb_check(prefix: 'kernel-patch-2.2.19-arm', release: '2.2', reference: '20010414')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.2.19-arm is vulnerable in Debian 2.2.\nUpgrade to kernel-patch-2.2.19-arm_20010414\n');
}
if (deb_check(prefix: 'kernel-patch-2.2.19-m68k', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.2.19-m68k is vulnerable in Debian 2.2.\nUpgrade to kernel-patch-2.2.19-m68k_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-patch-2.2.19-powerpc', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.2.19-powerpc is vulnerable in Debian 2.2.\nUpgrade to kernel-patch-2.2.19-powerpc_2.2.19-2\n');
}
if (deb_check(prefix: 'kernel-source-2.2.19', release: '2.2', reference: '2.2.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.2.19 is vulnerable in Debian 2.2.\nUpgrade to kernel-source-2.2.19_2.2.19-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
