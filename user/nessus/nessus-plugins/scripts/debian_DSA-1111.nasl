# This script was automatically generated from the dsa-1111
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that a race condition in the process filesystem can lead
to privilege escalation.
The following matrix explains which kernel version for which architecture
fixes the problem mentioned above:
The initial advisory lacked builds for the IBM S/390, Motorola 680x0 and HP
Precision architectures, which are now provided. Also, the kernels for the
FAI installer have been updated.
We recommend that you upgrade your kernel package immediately and reboot
the machine. If you have built a custom kernel from the kernel source
package, you will need to rebuild to take advantage of these fixes.


Solution : http://www.debian.org/security/2006/dsa-1111
Risk factor : High';

if (description) {
 script_id(22653);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1111");
 script_cve_id("CVE-2006-3626");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1111] DSA-1111-2 kernel-source-2.6.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1111-2 kernel-source-2.6.8");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fai-kernels', release: '3.1', reference: '1.9.1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fai-kernels is vulnerable in Debian 3.1.\nUpgrade to fai-kernels_1.9.1sarge3\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3', release: '3.1', reference: '2.6.8-15sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3_2.6.8-15sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power3-smp_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-power4-smp_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-build-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-build-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-build-2.6.8-3-powerpc-smp_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-doc-2.6.8', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-doc-2.6.8_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-itanium-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6-mckinley-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-generic_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-k8_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-amd64-k8-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-em64t-p4_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-12-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-12-em64t-p4-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3', release: '3.1', reference: '2.6.8-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3_2.6.8-5sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-32-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-386_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-64-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-686-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-generic_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-itanium-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-k7-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-mckinley-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc32_2.6.8-15sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64_2.6.8-15sarge4\n');
}
if (deb_check(prefix: 'kernel-headers-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-headers-2.6.8-3-sparc64-smp_2.6.8-15sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6-itanium-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-itanium-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6-mckinley-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-generic', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-generic_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-k8 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-k8_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-amd64-k8-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-amd64-k8-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-amd64-k8-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-em64t-p4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-em64t-p4_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-12-em64t-p4-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-12-em64t-p4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-12-em64t-p4-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-32', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-32-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-32-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-32-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-386', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-386 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-386_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-64-smp', release: '3.1', reference: '2.6.8-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-64-smp_2.6.8-6sarge3\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-686-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-686-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-686-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-generic', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-generic is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-generic_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-itanium-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-itanium-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-itanium-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-k7-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-k7-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-k7-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-mckinley-smp', release: '3.1', reference: '2.6.8-14sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-mckinley-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-mckinley-smp_2.6.8-14sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power3-smp', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power3-smp_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-power4-smp', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-power4-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-power4-smp_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-powerpc-smp', release: '3.1', reference: '2.6.8-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-powerpc-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-powerpc-smp_2.6.8-12sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390', release: '3.1', reference: '2.6.8-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390_2.6.8-5sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390-tape', release: '3.1', reference: '2.6.8-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390-tape is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390-tape_2.6.8-5sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-s390x', release: '3.1', reference: '2.6.8-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-s390x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-s390x_2.6.8-5sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-smp', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-smp_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc32', release: '3.1', reference: '2.6.8-15sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc32 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc32_2.6.8-15sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64', release: '3.1', reference: '2.6.8-15sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64_2.6.8-15sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-3-sparc64-smp', release: '3.1', reference: '2.6.8-15sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-3-sparc64-smp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-3-sparc64-smp_2.6.8-15sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-amiga', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-amiga is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-amiga_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-atari', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-atari is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-atari_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-bvme6000', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-bvme6000 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-bvme6000_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-hp', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-hp is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-hp_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mac', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mac is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mac_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme147', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme147 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme147_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-mvme16x', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-mvme16x is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-mvme16x_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-q40', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-q40 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-q40_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-image-2.6.8-sun3', release: '3.1', reference: '2.6.8-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.6.8-sun3 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.6.8-sun3_2.6.8-4sarge4\n');
}
if (deb_check(prefix: 'kernel-patch-2.6.8-s390', release: '3.1', reference: '2.6.8-5sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.6.8-s390 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-2.6.8-s390_2.6.8-5sarge4\n');
}
if (deb_check(prefix: 'kernel-patch-debian-2.6.8', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-debian-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-patch-debian-2.6.8_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-source-2.6.8', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.6.8_2.6.8-16sarge4\n');
}
if (deb_check(prefix: 'kernel-tree-2.6.8', release: '3.1', reference: '2.6.8-16sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-tree-2.6.8 is vulnerable in Debian 3.1.\nUpgrade to kernel-tree-2.6.8_2.6.8-16sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
