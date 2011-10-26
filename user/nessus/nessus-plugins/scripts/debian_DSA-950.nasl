# This script was automatically generated from the dsa-950
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" and Chris Evans discovered several heap based buffer
overflows in xpdf which are also present in CUPS, the Common UNIX
Printing System, and which can lead to a denial of service by crashing
the application or possibly to the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 1.1.14-5woody14.
CUPS doesn\'t use the xpdf source anymore since 1.1.22-7, when it switched
to using xpdf-utils for PDF processing.
We recommend that you upgrade your CUPS packages.


Solution : http://www.debian.org/security/2006/dsa-950
Risk factor : High';

if (description) {
 script_id(22816);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "950");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA950] DSA-950-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-950-1 cupsys");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.0.\nUpgrade to cupsys_1.1.14-5woody14\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 3.0.\nUpgrade to cupsys-bsd_1.1.14-5woody14\n');
}
if (deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-client is vulnerable in Debian 3.0.\nUpgrade to cupsys-client_1.1.14-5woody14\n');
}
if (deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-pstoraster is vulnerable in Debian 3.0.\nUpgrade to cupsys-pstoraster_1.1.14-5woody14\n');
}
if (deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2 is vulnerable in Debian 3.0.\nUpgrade to libcupsys2_1.1.14-5woody14\n');
}
if (deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-dev is vulnerable in Debian 3.0.\nUpgrade to libcupsys2-dev_1.1.14-5woody14\n');
}
if (deb_check(prefix: 'cupsys', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.1.\nUpgrade to cupsys_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 3.1.\nUpgrade to cupsys-bsd_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'cupsys-client', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-client is vulnerable in Debian 3.1.\nUpgrade to cupsys-client_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'libcupsimage2', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsimage2 is vulnerable in Debian 3.1.\nUpgrade to libcupsimage2_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'libcupsimage2-dev', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsimage2-dev is vulnerable in Debian 3.1.\nUpgrade to libcupsimage2-dev_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'libcupsys2', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2 is vulnerable in Debian 3.1.\nUpgrade to libcupsys2_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'libcupsys2-dev', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-dev is vulnerable in Debian 3.1.\nUpgrade to libcupsys2-dev_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'libcupsys2-gnutls10', release: '3.1', reference: '1.1.23-10sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-gnutls10 is vulnerable in Debian 3.1.\nUpgrade to libcupsys2-gnutls10_1.1.23-10sarge1\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian woody.\nUpgrade to cupsys_1.1.14-5woody14\n');
}
if (w) { security_hole(port: 0, data: desc); }
