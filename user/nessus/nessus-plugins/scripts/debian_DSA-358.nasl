# This script was automatically generated from the dsa-358
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A number of vulnerabilities have been discovered in the Linux kernel.
This advisory covers only the i386 and alpha architectures.  Other
architectures will be covered by separate advisories.
For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-13,
kernel-image-2.4.18-1-i386 version 2.4.18-11, and
kernel-image-2.4.18-i386bf version 2.4.18-5woody4.
For the stable distribution (woody) on the alpha architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-13 and
kernel-image-2.4.18-1-alpha version 2.4.18-10.
For the unstable distribution (sid) these problems are fixed in
kernel-source-2.4.20 version 2.4.20-9.
We recommend that you update your kernel packages.
If you are using the kernel installed by the installation system when
the "bf24" option is selected (for a 2.4.x kernel), you should install
the kernel-image-2.4.18-bf2.4 package.  If you installed a different
kernel-image package after installation, you should install the
corresponding 2.4.18-1 kernel.  You may use the table below as a
guide.

   | If "uname -r" shows: | Install this package:
   | 2.4.18-bf2.4         | kernel-image-2.4.18-bf2.4
   | 2.4.18-386           | kernel-image-2.4.18-1-386
   | 2.4.18-586tsc        | kernel-image-2.4.18-1-586tsc
   | 2.4.18-686           | kernel-image-2.4.18-1-686
   | 2.4.18-686-smp       | kernel-image-2.4.18-1-686-smp
   | 2.4.18-k6            | kernel-image-2.4.18-1-k6
   | 2.4.18-k7            | kernel-image-2.4.18-1-k7


NOTE: This kernel is binary compatible with the previous kernel
security update, but not binary compatible with the corresponding
kernel included in Debian 3.0r1.  If you have not already applied the
previous security update (kernel-image-2.4.18-bf2.4 version
2.4.18-5woody1 or any of the 2.4.18-1-* kernels), then any custom
modules will need to be rebuilt in order to work with the new kernel.
New PCMCIA modules are provided for all of the above kernels.
NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel.  Remember to read carefully
and follow the instructions given during the kernel upgrade process.


Solution : http://www.debian.org/security/2003/dsa-358
Risk factor : High';

if (description) {
 script_id(15195);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "358");
 script_cve_id("CVE-2003-0018", "CVE-2003-0461", "CVE-2003-0462", "CVE-2003-0476", "CVE-2003-0501", "CVE-2003-0550", "CVE-2003-0551");
 script_bugtraq_id(10330, 8042, 8233);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA358] DSA-358-4 linux-kernel-2.4.18");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-358-4 linux-kernel-2.4.18");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.18', release: '3.0', reference: '2.4.18-13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.18_2.4.18-13\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1', release: '3.0', reference: '2.4.18-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1_2.4.18-10\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-386', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-386_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-586tsc_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-686', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-686_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-686-smp_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-generic', release: '3.0', reference: '2.4.18-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-generic is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-generic_2.4.18-10\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-k6', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-k6_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-k7', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-k7_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-smp', release: '3.0', reference: '2.4.18-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-smp_2.4.18-10\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-bf2.4', release: '3.0', reference: '2.4.18-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-bf2.4 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-bf2.4_2.4.18-5woody4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-386', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-386_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-586tsc_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-686', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-686_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-686-smp_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-generic', release: '3.0', reference: '2.4.18-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-generic is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-generic_2.4.18-10\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-k6', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-k6_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-k7', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-k7_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-smp', release: '3.0', reference: '2.4.18-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-smp_2.4.18-10\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-bf2.4', release: '3.0', reference: '2.4.18-5woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-bf2.4 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-bf2.4_2.4.18-5woody4\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-386', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-386_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-586tsc_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-686_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-686-smp_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-k6', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-k6_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-k7', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-k7_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18', release: '3.0', reference: '2.4.18-13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.18_2.4.18-13\n');
}
if (deb_check(prefix: 'kernel-source-2.4.20', release: '3.1', reference: '2.4.20-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.20 is vulnerable in Debian 3.1.\nUpgrade to kernel-source-2.4.20_2.4.20-9\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18', release: '3.0', reference: '2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18 is vulnerable in Debian woody.\nUpgrade to kernel-source-2.4.18_2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
