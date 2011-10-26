# This script was automatically generated from the dsa-232
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Multiple vulnerabilities were discovered in the Common Unix Printing
System (CUPS).  Several of these issues represent the potential for a
remote compromise or denial of service.  The Common Vulnerabilities
and Exposures project identifies the following problems:
Even though we tried very hard to fix all problems in the packages for
potato as well, the packages may still contain other security related
problems.  Hence, we advise users of potato systems using CUPS to
upgrade to woody soon.
For the current stable distribution (woody), these problems have been fixed
in version 1.1.14-4.3.
For the old stable distribution (potato), these problems have been fixed
in version 1.0.4-12.1.
For the unstable distribution (sid), these problems have been fixed in
version 1.1.18-1.
We recommend that you upgrade your CUPS packages immediately.


Solution : http://www.debian.org/security/2003/dsa-232
Risk factor : High';

if (description) {
 script_id(15069);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "232");
 script_cve_id("CVE-2002-1368", "CVE-2002-1383", "CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372");
 script_bugtraq_id(6435, 6436, 6437, 6438, 6439, 6440, 6475);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA232] DSA-232-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-232-1 cupsys");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 2.2.\nUpgrade to cupsys_1.0.4-12.1\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '2.2', reference: '1.0.4-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 2.2.\nUpgrade to cupsys-bsd_1.0.4-12.1\n');
}
if (deb_check(prefix: 'libcupsys1', release: '2.2', reference: '1.0.4-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys1 is vulnerable in Debian 2.2.\nUpgrade to libcupsys1_1.0.4-12.1\n');
}
if (deb_check(prefix: 'libcupsys1-dev', release: '2.2', reference: '1.0.4-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys1-dev is vulnerable in Debian 2.2.\nUpgrade to libcupsys1-dev_1.0.4-12.1\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-4.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.0.\nUpgrade to cupsys_1.1.14-4.4\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-4.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 3.0.\nUpgrade to cupsys-bsd_1.1.14-4.4\n');
}
if (deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-4.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-client is vulnerable in Debian 3.0.\nUpgrade to cupsys-client_1.1.14-4.4\n');
}
if (deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-4.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-pstoraster is vulnerable in Debian 3.0.\nUpgrade to cupsys-pstoraster_1.1.14-4.4\n');
}
if (deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-4.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2 is vulnerable in Debian 3.0.\nUpgrade to libcupsys2_1.1.14-4.4\n');
}
if (deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-4.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-dev is vulnerable in Debian 3.0.\nUpgrade to libcupsys2-dev_1.1.14-4.4\n');
}
if (deb_check(prefix: 'cupsys', release: '3.1', reference: '1.1.18-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.1.\nUpgrade to cupsys_1.1.18-1\n');
}
if (deb_check(prefix: 'cupsys', release: '2.2', reference: '1.0.4-12.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian potato.\nUpgrade to cupsys_1.0.4-12.1\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-4.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian woody.\nUpgrade to cupsys_1.1.14-4.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
