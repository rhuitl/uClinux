# This script was automatically generated from the dsa-417
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Starzetz discovered a flaw in bounds checking in mremap() in the
Linux kernel (present in version 2.4.x and 2.6.x) which may allow a
local attacker to gain root privileges.  Version 2.2 is not affected
by this bug.
Andrew Morton discovered a missing boundary check for the brk system
call which can be used to craft a local root exploit.
For the stable distribution (woody) these problems have been fixed in
version 2.4.18-12 for the alpha architecture and in
version 2.4.18-1woody3 for the powerpc architecture.
For the unstable distribution (sid) these problems will be fixed soon
with newly uploaded packages.
We recommend that you upgrade your kernel packages.  These problems have
been fixed in the upstream version 2.4.24 as well.


Solution : http://www.debian.org/security/2004/dsa-417
Risk factor : High';

if (description) {
 script_id(15254);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "417");
 script_cve_id("CVE-2003-0961", "CVE-2003-0985");
 script_bugtraq_id(9356);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA417] DSA-417-1 linux-kernel-2.4.18-powerpc+alpha");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-417-1 linux-kernel-2.4.18-powerpc+alpha");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.18', release: '3.0', reference: '2.4.18-14.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.18_2.4.18-14.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18', release: '3.0', reference: '2.4.18-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18_2.4.18-1woody3\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1', release: '3.0', reference: '2.4.18-12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1_2.4.18-12\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-generic', release: '3.0', reference: '2.4.18-12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-generic is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-generic_2.4.18-12\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-smp', release: '3.0', reference: '2.4.18-12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-smp_2.4.18-12\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-generic', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-generic is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-generic_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-smp', release: '3.0', reference: '2.4.18-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-smp_2.4.18-11\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-newpmac', release: '3.0', reference: '2.4.18-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-newpmac is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-newpmac_2.4.18-1woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-powerpc is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-powerpc_2.4.18-1woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-powerpc-smp', release: '3.0', reference: '2.4.18-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-powerpc-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-powerpc-smp_2.4.18-1woody3\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.18-powerpc', release: '3.0', reference: '2.4.18-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.18-powerpc is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.18-powerpc_2.4.18-1woody3\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18', release: '3.0', reference: '2.4.18-14.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.18_2.4.18-14.1\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.18-powerpc,', release: '3.0', reference: '2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.18-powerpc, is vulnerable in Debian woody.\nUpgrade to kernel-patch-2.4.18-powerpc,_2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
