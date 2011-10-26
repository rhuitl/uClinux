# This script was automatically generated from the dsa-444
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Starzetz and Wojciech Purczynski of isec.pl <a
href="http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt">discovered</a> a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call.  Due to missing function return value check
of internal functions a local attacker can gain root privileges.
For the stable distribution (woody) this problem has been fixed in
version 011226.16 of ia64 kernel source and images.
Other architectures are or will be mentioned in a separate advisory
respectively or are not affected (m68k).
For the unstable distribution (sid) this problem will be fixed in version
2.4.24-3.
This problem is also fixed in the upstream version of Linux 2.4.25 and
2.6.3.
We recommend that you upgrade your Linux kernel packages immediately.
Vulnerability matrix for CVE-2004-0077


Solution : http://www.debian.org/security/2004/dsa-444
Risk factor : High';

if (description) {
 script_id(15281);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "444");
 script_cve_id("CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA444] DSA-444-1 linux-kernel-2.4.17-ia64");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-444-1 linux-kernel-2.4.17-ia64");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-headers-2.4.17-ia64', release: '3.0', reference: '011226.16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17-ia64 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17-ia64_011226.16\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-itanium', release: '3.0', reference: '011226.16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-itanium is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-itanium_011226.16\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-itanium-smp', release: '3.0', reference: '011226.16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-itanium-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-itanium-smp_011226.16\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-mckinley', release: '3.0', reference: '011226.16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-mckinley is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-mckinley_011226.16\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-mckinley-smp', release: '3.0', reference: '011226.16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-mckinley-smp is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-mckinley-smp_011226.16\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17-ia64', release: '3.0', reference: '011226.16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17-ia64 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17-ia64_011226.16\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-ia64', release: '3.1', reference: '2.4.24-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-ia64 is vulnerable in Debian 3.1.\nUpgrade to kernel-image-2.4.17-ia64_2.4.24-3\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-ia64', release: '3.0', reference: '011226')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-ia64 is vulnerable in Debian woody.\nUpgrade to kernel-image-2.4.17-ia64_011226\n');
}
if (w) { security_hole(port: 0, data: desc); }
