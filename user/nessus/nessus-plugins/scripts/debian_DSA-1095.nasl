# This script was automatically generated from the dsa-1095
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in the FreeType 2 font engine.
The Common vulnerabilities and Exposures project identifies the
following problems:
    Several integer underflows have been discovered which could allow
    remote attackers to cause a denial of service.
    Chris Evans discovered several integer overflows that lead to a
    denial of service or could possibly even lead to the execution of
    arbitrary code.
    Several more integer overflows have been discovered which could
    possibly lead to the execution of arbitrary code.
    A null pointer dereference could cause a denial of service.
For the old stable distribution (woody) these problems have been fixed in
version 2.0.9-1woody1.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.7-2.5.
For the unstable distribution (sid) these problems will be fixed soon
We recommend that you upgrade your libfreetype packages.


Solution : http://www.debian.org/security/2006/dsa-1095
Risk factor : High';

if (description) {
 script_id(22637);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1095");
 script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2493", "CVE-2006-2661");
 script_bugtraq_id(18034);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1095] DSA-1095-1 freetype");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1095-1 freetype");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freetype2-demos', release: '3.0', reference: '2.0.9-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freetype2-demos is vulnerable in Debian 3.0.\nUpgrade to freetype2-demos_2.0.9-1woody1\n');
}
if (deb_check(prefix: 'libfreetype6', release: '3.0', reference: '2.0.9-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreetype6 is vulnerable in Debian 3.0.\nUpgrade to libfreetype6_2.0.9-1woody1\n');
}
if (deb_check(prefix: 'libfreetype6-dev', release: '3.0', reference: '2.0.9-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreetype6-dev is vulnerable in Debian 3.0.\nUpgrade to libfreetype6-dev_2.0.9-1woody1\n');
}
if (deb_check(prefix: 'freetype2-demos', release: '3.1', reference: '2.1.7-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freetype2-demos is vulnerable in Debian 3.1.\nUpgrade to freetype2-demos_2.1.7-2.5\n');
}
if (deb_check(prefix: 'libfreetype6', release: '3.1', reference: '2.1.7-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreetype6 is vulnerable in Debian 3.1.\nUpgrade to libfreetype6_2.1.7-2.5\n');
}
if (deb_check(prefix: 'libfreetype6-dev', release: '3.1', reference: '2.1.7-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreetype6-dev is vulnerable in Debian 3.1.\nUpgrade to libfreetype6-dev_2.1.7-2.5\n');
}
if (deb_check(prefix: 'freetype', release: '3.1', reference: '2.1.7-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freetype is vulnerable in Debian sarge.\nUpgrade to freetype_2.1.7-2.5\n');
}
if (deb_check(prefix: 'freetype', release: '3.0', reference: '2.0.9-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freetype is vulnerable in Debian woody.\nUpgrade to freetype_2.0.9-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
