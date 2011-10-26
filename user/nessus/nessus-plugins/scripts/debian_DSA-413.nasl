# This script was automatically generated from the dsa-413
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Starzetz href="http://isec.pl/vulnerabilities/isec-0013-mremap.txt"discovered</A> a flaw in bounds checking in mremap() in the
Linux kernel (present in version 2.4.x and 2.6.x) which may allow
a local attacker to gain root privileges.
Version 2.2 is not affected by this bug, since it doesn\'t support the
MREMAP_FIXED flag (as href="http://seclists.org/lists/fulldisclosure/2004/Jan/0095.html"clarified later</A>).
For the stable distribution (woody) this problem has been fixed in
kernel-source version 2.4.18-14.1 and kernel-images versions
2.4.18-12.1 and 2.4.18-5woody6 (bf) for the i386 architecture.
For the unstable distribution (sid) this problem will be fixed soon
with newly uploaded packages.
We recommend that you upgrade your kernel packages.  This problem has
been fixed in the upstream version 2.4.24 as well.


Solution : http://www.debian.org/security/2004/dsa-413
Risk factor : High';

if (description) {
 script_id(15250);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "413");
 script_cve_id("CVE-2003-0985");
 script_bugtraq_id(9356);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA413] DSA-413-2 linux-kernel-2.4.18");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-413-2 linux-kernel-2.4.18");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.18', release: '3.0', reference: '2.4.18-14.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.18_2.4.18-14.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-386', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-386_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-586tsc_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-686', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-686_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-686-smp_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-k6_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-1-k7_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.18-bf2.4', release: '3.0', reference: '2.4.18-5woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.18-bf2.4 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.18-bf2.4_2.4.18-5woody6\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-386', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-386_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-586tsc_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-686', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-686_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-686-smp_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-k6_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-1-k7_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-image-2.4.18-bf2.4', release: '3.0', reference: '2.4.18-5woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.18-bf2.4 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.18-bf2.4_2.4.18-5woody6\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-386', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-386 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-386_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-586tsc', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-586tsc is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-586tsc_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-686 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-686_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-686-smp', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-686-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-686-smp_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-k6', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-k6 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-k6_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-pcmcia-modules-2.4.18-1-k7', release: '3.0', reference: '2.4.18-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-pcmcia-modules-2.4.18-1-k7 is vulnerable in Debian 3.0.\nUpgrade to kernel-pcmcia-modules-2.4.18-1-k7_2.4.18-12.1\n');
}
if (deb_check(prefix: 'kernel-source-2.4.18', release: '3.0', reference: '2.4.18-14.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.18 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.18_2.4.18-14.1\n');
}
if (deb_check(prefix: 'kernel-source', release: '3.0', reference: '2.4.18-14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source is vulnerable in Debian woody.\nUpgrade to kernel-source_2.4.18-14\n');
}
if (w) { security_hole(port: 0, data: desc); }
