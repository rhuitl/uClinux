# This script was automatically generated from the dsa-317
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The CUPS print server in Debian is vulnerable to a denial of service
when an HTTP request is received without being properly terminated.
For the stable distribution (woody) this problem has been fixed in
version 1.1.14-5.
For the old stable distribution (potato) this problem has been fixed
in version 1.0.4-12.2.
For the unstable distribution (sid) this problem is fixed in
version 1.1.19final-1.
We recommend that you update your cupsys package.


Solution : http://www.debian.org/security/2003/dsa-317
Risk factor : High';

if (description) {
 script_id(15154);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "317");
 script_cve_id("CVE-2003-0195");
 script_bugtraq_id(7637);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA317] DSA-317-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-317-1 cupsys");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 2.2.\nUpgrade to cupsys_1.0.4-12.2\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '2.2', reference: '1.0.4-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 2.2.\nUpgrade to cupsys-bsd_1.0.4-12.2\n');
}
if (deb_check(prefix: 'libcupsys1', release: '2.2', reference: '1.0.4-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys1 is vulnerable in Debian 2.2.\nUpgrade to libcupsys1_1.0.4-12.2\n');
}
if (deb_check(prefix: 'libcupsys1-dev', release: '2.2', reference: '1.0.4-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys1-dev is vulnerable in Debian 2.2.\nUpgrade to libcupsys1-dev_1.0.4-12.2\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.0.\nUpgrade to cupsys_1.1.14-5\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 3.0.\nUpgrade to cupsys-bsd_1.1.14-5\n');
}
if (deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-client is vulnerable in Debian 3.0.\nUpgrade to cupsys-client_1.1.14-5\n');
}
if (deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-pstoraster is vulnerable in Debian 3.0.\nUpgrade to cupsys-pstoraster_1.1.14-5\n');
}
if (deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2 is vulnerable in Debian 3.0.\nUpgrade to libcupsys2_1.1.14-5\n');
}
if (deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-dev is vulnerable in Debian 3.0.\nUpgrade to libcupsys2-dev_1.1.14-5\n');
}
if (deb_check(prefix: 'cupsys', release: '3.1', reference: '1.1.19final-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.1.\nUpgrade to cupsys_1.1.19final-1\n');
}
if (deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-12.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian potato.\nUpgrade to cupsys_1.0.4-12.2\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian woody.\nUpgrade to cupsys_1.1.14-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
