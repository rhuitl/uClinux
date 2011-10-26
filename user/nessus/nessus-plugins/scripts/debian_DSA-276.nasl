# This script was automatically generated from the dsa-276
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The kernel module loader in Linux 2.2 and Linux 2.4 kernels has a flaw
in ptrace.  This hole allows local users to obtain root privileges by
using ptrace to attach to a child process that is spawned by the
kernel.  Remote exploitation of this hole is not possible.
This advisory only covers kernel packages for the S/390 architecture.
Other architectures will be covered by separate advisories.
For the stable distribution (woody) this problem has been fixed in the
following versions:
The old stable distribution (potato) is not affected by this problem
for this architecture since s390 was first released with Debian
GNU/Linux 3.0 (woody).
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your kernel-images packages immediately.


Solution : http://www.debian.org/security/2003/dsa-276
Risk factor : High';

if (description) {
 script_id(15113);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "276");
 script_cve_id("CVE-2003-0127");
 script_bugtraq_id(7112);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA276] DSA-276-1 linux-kernel-s390");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-276-1 linux-kernel-s390");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kernel-headers-2.4.17', release: '3.0', reference: '2.4.17-2.woody.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-headers-2.4.17 is vulnerable in Debian 3.0.\nUpgrade to kernel-headers-2.4.17_2.4.17-2.woody.2.2\n');
}
if (deb_check(prefix: 'kernel-image-2.4.17-s390', release: '3.0', reference: '2.4.17-2.woody.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-image-2.4.17-s390 is vulnerable in Debian 3.0.\nUpgrade to kernel-image-2.4.17-s390_2.4.17-2.woody.2.2\n');
}
if (deb_check(prefix: 'kernel-patch-2.4.17-s390', release: '3.0', reference: '0.0.20020816-0.woody.1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kernel-patch-2.4.17-s390 is vulnerable in Debian 3.0.\nUpgrade to kernel-patch-2.4.17-s390_0.0.20020816-0.woody.1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
