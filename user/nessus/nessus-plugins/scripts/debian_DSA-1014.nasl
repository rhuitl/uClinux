# This script was automatically generated from the dsa-1014
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Aviram Jenik and Damyan Ivanov discovered a buffer overflow in
firebird2, an RDBMS based on InterBase 6.0 code, that allows remote
attackers to crash.
The old stable distribution (woody) does not contain firebird2 packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.5.1-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.5.3.4870-3
We recommend that you upgrade your firebird2 packages.


Solution : http://www.debian.org/security/2006/dsa-1014
Risk factor : High';

if (description) {
 script_id(22556);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1014");
 script_cve_id("CVE-2004-2043");
 script_bugtraq_id(10446);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1014] DSA-1014-1 firebird2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1014-1 firebird2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'firebird2', release: '', reference: '1.5.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2 is vulnerable in Debian .\nUpgrade to firebird2_1.5.3\n');
}
if (deb_check(prefix: 'firebird2-classic-server', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2-classic-server is vulnerable in Debian 3.1.\nUpgrade to firebird2-classic-server_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'firebird2-dev', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2-dev is vulnerable in Debian 3.1.\nUpgrade to firebird2-dev_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'firebird2-examples', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2-examples is vulnerable in Debian 3.1.\nUpgrade to firebird2-examples_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'firebird2-server-common', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2-server-common is vulnerable in Debian 3.1.\nUpgrade to firebird2-server-common_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'firebird2-super-server', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2-super-server is vulnerable in Debian 3.1.\nUpgrade to firebird2-super-server_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'firebird2-utils-classic', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2-utils-classic is vulnerable in Debian 3.1.\nUpgrade to firebird2-utils-classic_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'firebird2-utils-super', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2-utils-super is vulnerable in Debian 3.1.\nUpgrade to firebird2-utils-super_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'libfirebird2-classic', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfirebird2-classic is vulnerable in Debian 3.1.\nUpgrade to libfirebird2-classic_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'libfirebird2-super', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfirebird2-super is vulnerable in Debian 3.1.\nUpgrade to libfirebird2-super_1.5.1-4sarge1\n');
}
if (deb_check(prefix: 'firebird2', release: '3.1', reference: '1.5.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package firebird2 is vulnerable in Debian sarge.\nUpgrade to firebird2_1.5.1-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
