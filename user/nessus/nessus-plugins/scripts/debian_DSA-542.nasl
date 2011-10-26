# This script was automatically generated from the dsa-542
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities were discovered in recent versions of Qt, a
commonly used graphic widget set, used in KDE for example.  The first
problem allows an attacker to execute arbitrary code, while the other
two only seem to pose a denial of service danger.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Chris Evans has discovered a heap-based overflow when handling
    8-bit RLE encoded BMP files.
    Marcus Meissner has discovered a crash condition in the XPM
    handling code, which is not yet fixed in Qt 3.3.
    Marcus Meissner has discovered a crash condition in the GIF
    handling code, which is not yet fixed in Qt 3.3.
For the stable distribution (woody) these problems have been fixed in
version 3.0.3-20020329-1woody2.
For the unstable distribution (sid) these problems have been fixed in
version 3.3.3-4 of qt-x11-free.
We recommend that you upgrade your qt packages.


Solution : http://www.debian.org/security/2004/dsa-542
Risk factor : High';

if (description) {
 script_id(15379);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "542");
 script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA542] DSA-542-1 qt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-542-1 qt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libqt3', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3 is vulnerable in Debian 3.0.\nUpgrade to libqt3_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqt3-dev', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3-dev is vulnerable in Debian 3.0.\nUpgrade to libqt3-dev_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqt3-mt', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3-mt is vulnerable in Debian 3.0.\nUpgrade to libqt3-mt_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqt3-mt-dev', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3-mt-dev is vulnerable in Debian 3.0.\nUpgrade to libqt3-mt-dev_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqt3-mt-mysql', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3-mt-mysql is vulnerable in Debian 3.0.\nUpgrade to libqt3-mt-mysql_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqt3-mt-odbc', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3-mt-odbc is vulnerable in Debian 3.0.\nUpgrade to libqt3-mt-odbc_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqt3-mysql', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3-mysql is vulnerable in Debian 3.0.\nUpgrade to libqt3-mysql_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqt3-odbc', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqt3-odbc is vulnerable in Debian 3.0.\nUpgrade to libqt3-odbc_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'libqxt0', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libqxt0 is vulnerable in Debian 3.0.\nUpgrade to libqxt0_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'qt3-doc', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qt3-doc is vulnerable in Debian 3.0.\nUpgrade to qt3-doc_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'qt3-tools', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qt3-tools is vulnerable in Debian 3.0.\nUpgrade to qt3-tools_3.0.3-20020329-1woody2\n');
}
if (deb_check(prefix: 'qt-copy', release: '3.1', reference: '3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qt-copy is vulnerable in Debian 3.1.\nUpgrade to qt-copy_3.3\n');
}
if (deb_check(prefix: 'qt-copy', release: '3.0', reference: '3.0.3-20020329-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qt-copy is vulnerable in Debian woody.\nUpgrade to qt-copy_3.0.3-20020329-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
