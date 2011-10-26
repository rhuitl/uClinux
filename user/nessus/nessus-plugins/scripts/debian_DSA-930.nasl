# This script was automatically generated from the dsa-930
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit project discovered a
format string attack in the logging code of smstools, which may be
exploited to execute arbitary code with root privileges.
The original advisory for this issue said that the old stable
distribution (woody) was not affected because it did not contain
smstools. This was incorrect, and the only change in this updated
advisory is the inclusion of corrected packages for woody.
For the old stable distribution (woody) this problem has been fixed in
version 1.5.0-2woody0.
For the stable distribution (sarge) this problem has been fixed in
version 1.14.8-1sarge0.
For the unstable distribution the package will be updated shortly.
We recommend that you upgrade your smstools package.


Solution : http://www.debian.org/security/2006/dsa-930
Risk factor : High';

if (description) {
 script_id(22796);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "930");
 script_cve_id("CVE-2006-0083");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA930] DSA-930-2 smstools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-930-2 smstools");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'smstools', release: '3.0', reference: '1.5.0-2woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smstools is vulnerable in Debian 3.0.\nUpgrade to smstools_1.5.0-2woody0\n');
}
if (deb_check(prefix: 'smstools', release: '3.1', reference: '1.14.8-1sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smstools is vulnerable in Debian 3.1.\nUpgrade to smstools_1.14.8-1sarge0\n');
}
if (deb_check(prefix: 'smstools', release: '3.1', reference: '1.14.8-1sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smstools is vulnerable in Debian sarge.\nUpgrade to smstools_1.14.8-1sarge0\n');
}
if (deb_check(prefix: 'smstools', release: '3.0', reference: '1.5.0-2woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package smstools is vulnerable in Debian woody.\nUpgrade to smstools_1.5.0-2woody0\n');
}
if (w) { security_hole(port: 0, data: desc); }
