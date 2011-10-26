# This script was automatically generated from the dsa-976
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Johnny Mast discovered a buffer overflow in libast, the library of
assorted spiffy things, that can lead to the execution of arbitary
code.  This library is used by eterm which is installed setgid uid
which leads to a vulnerability to alter the utmp file.
For the old stable distribution (woody) this problem has been fixed in
version 0.4-3woody2.
For the stable distribution (sarge) this problem has been fixed in
version 0.6-0pre2003010606sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your libast packages.


Solution : http://www.debian.org/security/2006/dsa-976
Risk factor : High';

if (description) {
 script_id(22842);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "976");
 script_cve_id("CVE-2006-0224");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA976] DSA-976-1 libast");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-976-1 libast");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libast1', release: '3.0', reference: '0.4-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libast1 is vulnerable in Debian 3.0.\nUpgrade to libast1_0.4-3woody2\n');
}
if (deb_check(prefix: 'libast1-dev', release: '3.0', reference: '0.4-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libast1-dev is vulnerable in Debian 3.0.\nUpgrade to libast1-dev_0.4-3woody2\n');
}
if (deb_check(prefix: 'libast2', release: '3.1', reference: '0.6-0pre2003010606sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libast2 is vulnerable in Debian 3.1.\nUpgrade to libast2_0.6-0pre2003010606sarge1\n');
}
if (deb_check(prefix: 'libast2-dev', release: '3.1', reference: '0.6-0pre2003010606sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libast2-dev is vulnerable in Debian 3.1.\nUpgrade to libast2-dev_0.6-0pre2003010606sarge1\n');
}
if (deb_check(prefix: 'libast,', release: '3.1', reference: '0.6-0pre2003010606sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libast, is vulnerable in Debian sarge.\nUpgrade to libast,_0.6-0pre2003010606sarge1\n');
}
if (deb_check(prefix: 'libast,', release: '3.0', reference: '0.4-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libast, is vulnerable in Debian woody.\nUpgrade to libast,_0.4-3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
