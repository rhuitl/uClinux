# This script was automatically generated from the dsa-1153
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Damian Put discovered a heap overflow vulnerability in the UPX
unpacker of the ClamAV anti-virus toolkit which could allow remote
attackers to execute arbitrary code or cause denial of service.
For the stable distribution (sarge) this problem has been fixed in
version 0.84-2.sarge.10.
For the stable distribution (sarge) this problem has been fixed in
version 0.88.4-0volatile1 in the volatile archive.
For the unstable distribution (sid) this problem has been fixed in
version 0.88.4-2.
We recommend that you upgrade your clamav packages.


Solution : http://www.debian.org/security/2006/dsa-1153
Risk factor : High';

if (description) {
 script_id(22695);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1153");
 script_cve_id("CVE-2006-4018");
 script_bugtraq_id(19381);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1153] DSA-1153-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1153-1 clamav");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'clamav', release: '', reference: '0.88.4-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian .\nUpgrade to clamav_0.88.4-2\n');
}
if (deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian 3.1.\nUpgrade to clamav_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'clamav-base', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-base is vulnerable in Debian 3.1.\nUpgrade to clamav-base_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'clamav-daemon', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-daemon is vulnerable in Debian 3.1.\nUpgrade to clamav-daemon_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'clamav-docs', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-docs is vulnerable in Debian 3.1.\nUpgrade to clamav-docs_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'clamav-freshclam', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-freshclam is vulnerable in Debian 3.1.\nUpgrade to clamav-freshclam_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'clamav-milter', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-milter is vulnerable in Debian 3.1.\nUpgrade to clamav-milter_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'clamav-testfiles', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-testfiles is vulnerable in Debian 3.1.\nUpgrade to clamav-testfiles_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'libclamav-dev', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libclamav-dev is vulnerable in Debian 3.1.\nUpgrade to libclamav-dev_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'libclamav1', release: '3.1', reference: '0.84-2.sarge.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libclamav1 is vulnerable in Debian 3.1.\nUpgrade to libclamav1_0.84-2.sarge.10\n');
}
if (deb_check(prefix: 'clamav', release: '3.1', reference: '0.88')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian sarge.\nUpgrade to clamav_0.88\n');
}
if (w) { security_hole(port: 0, data: desc); }
