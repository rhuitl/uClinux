# This script was automatically generated from the dsa-440
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several local root exploits have been discovered recently in the Linux
kernel.  This security advisory updates the PowerPC/Apus kernel for
Debian GNU/Linux.  The Common Vulnerabilities and Exposures project
identifies the following problems that are fixed with this update:
   An integer overflow in brk() system call (do_brk() function) for
   Linux allows a local attacker to gain root privileges.  Fixed
   upstream in Linux 2.4.23.
   Paul Starzetz discovered
   a flaw in bounds checking in mremap() in
   the Linux kernel (present in version 2.4.x and 2.6.x) which may
   allow a local attacker to gain root privileges.  Version 2.2 is not
   affected by this bug.  Fixed upstream in Linux 2.4.24.
   Paul Starzetz and Wojciech Purczynski of isec.pl <a
   href="http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt">discovered</a> a
   critical security vulnerability in the memory management code of
   Linux inside the mremap(2) system call.  Due to missing function
   return value check of internal functions a local attacker can gain
   root privileges.  Fixed upstream in Linux 2.4.25 and 2.6.3.
For the stable distribution (woody) these problems have been fixed in
version 2.4.17-4 of powerpc/apus images.
Other architectures will probably be mentioned in a separate advisory or
are not affected (m68k).
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your Linux kernel packages immediately.


Solution : http://www.debian.org/security/2004/dsa-440
Risk factor : High';

if (description) {
 script_id(15277);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "440");
 script_cve_id("CVE-2003-0961", "CVE-2003-0985", "CVE-2004-0077");
 script_bugtraq_id(9686);
 script_xref(name: "CERT", value: "981222");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA440] DSA-440-1 linux-kernel-2.4.17-powerpc-apus");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-440-1 linux-kernel-2.4.17-powerpc-apus");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-doc-2.4.17', release: '3.0', reference: '2.4.17-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-doc-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-doc-2.4.17_2.4.17-1woody2\n');
}
if (deb_check(prefix: 'kernel-headers-2.4.17-apus', release: '3.0', reference: '2.4.17-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17-apus_2.4.17-4\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-apus', release: '3.0', reference: '2.4.17-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-apus_2.4.17-4\n');
}
if (deb_check(prefix: 'kernel-image-apus', release: '3.0', reference: '2.4.17-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-image-apus_2.4.17-4\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-apus', release: '3.0', reference: '2.4.17-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-apus is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-apus_2.4.17-4\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17', release: '3.0', reference: '2.4.17-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-source-2.4.17_2.4.17-1woody2\n');
}
if (deb_check(prefix: 'kernel-source-2.4.17,', release: '3.0', reference: '2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-source-2.4.17, is vulnerable in Debian woody.\nUpgrade to kernel-source-2.4.17,_2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
