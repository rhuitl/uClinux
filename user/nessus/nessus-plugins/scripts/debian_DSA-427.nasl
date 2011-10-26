# This script was automatically generated from the dsa-427
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
For the stable distribution (woody) this problem has been fixed in
version 2.4.17-0.020226.2.woody3 the mips and mipsel architectures.
For the unstable distribution (sid) this problem will be fixed soon
with newly uploaded packages.
We recommend that you upgrade your kernel packages.  This problem has
been fixed in the upstream version 2.4.24 as well.


Solution : http://www.debian.org/security/2004/dsa-427
Risk factor : High';

if (description) {
 script_id(15264);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "427");
 script_cve_id("CVE-2003-0985");
 script_bugtraq_id(9356);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA427] DSA-427-1 linux-kernel-2.4.17-mips+mipsel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-427-1 linux-kernel-2.4.17-mips+mipsel");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-0.020226.2.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17_2.4.17-0.020226.2.woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r3k-kn02', release: '3.0', reference: '2.4.17-0.020226.2.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r3k-kn02 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r3k-kn02_2.4.17-0.020226.2.woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-ip22_2.4.17-0.020226.2.woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r4k-kn04', release: '3.0', reference: '2.4.17-0.020226.2.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r4k-kn04 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r4k-kn04_2.4.17-0.020226.2.woody3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-r5k-ip22', release: '3.0', reference: '2.4.17-0.020226.2.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-r5k-ip22 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-r5k-ip22_2.4.17-0.020226.2.woody3\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-mips_2.4.17-0.020226.2.woody3\n');
}
if (deb_check(prefix: 'mips-tools', release: '3.0', reference: '2.4.17-0.020226.2.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mips-tools is vulnerable in Debian 3.0.\nUpgrade to mips-tools_2.4.17-0.020226.2.woody3\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-mips', release: '3.0', reference: '2.4.17-0.020226.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-mips is vulnerable in Debian woody.\nUpgrade to kernel-patch-2.4.17-mips_2.4.17-0.020226.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
