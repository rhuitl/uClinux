# This script was automatically generated from the dsa-573
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered several integer overflows in xpdf, that are
also present in CUPS, the Common UNIX Printing System, which can be
exploited remotely by a specially crafted PDF document.
For the stable distribution (woody) these problems have been fixed in
version 1.1.14-5woody10.
For the unstable distribution (sid) these problems have been fixed in
version 1.1.20final+rc1-10.
We recommend that you upgrade your CUPS packages.


Solution : http://www.debian.org/security/2004/dsa-573
Risk factor : High';

if (description) {
 script_id(15671);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "573");
 script_cve_id("CVE-2004-0888");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA573] DSA-573-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-573-1 cupsys");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.0.\nUpgrade to cupsys_1.1.14-5woody10\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 3.0.\nUpgrade to cupsys-bsd_1.1.14-5woody10\n');
}
if (deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-client is vulnerable in Debian 3.0.\nUpgrade to cupsys-client_1.1.14-5woody10\n');
}
if (deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-pstoraster is vulnerable in Debian 3.0.\nUpgrade to cupsys-pstoraster_1.1.14-5woody10\n');
}
if (deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2 is vulnerable in Debian 3.0.\nUpgrade to libcupsys2_1.1.14-5woody10\n');
}
if (deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-dev is vulnerable in Debian 3.0.\nUpgrade to libcupsys2-dev_1.1.14-5woody10\n');
}
if (deb_check(prefix: 'cupsys', release: '3.1', reference: '1.1.20final+rc1-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.1.\nUpgrade to cupsys_1.1.20final+rc1-10\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian woody.\nUpgrade to cupsys_1.1.14-5woody10\n');
}
if (w) { security_hole(port: 0, data: desc); }
