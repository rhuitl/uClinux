# This script was automatically generated from the dsa-1116
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Henning Makholm discovered a buffer overflow in the XCF loading code
of Gimp, an image editing program. Opening a specially crafted XCF
image might cause the application to execute arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.6-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.11-3.1.
We recommend that you upgrade your gimp package.


Solution : http://www.debian.org/security/2006/dsa-1116
Risk factor : High';

if (description) {
 script_id(22658);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1116");
 script_cve_id("CVE-2006-3404");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1116] DSA-1116-1 gimp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1116-1 gimp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gimp', release: '', reference: '2.2.11-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp is vulnerable in Debian .\nUpgrade to gimp_2.2.11-3.1\n');
}
if (deb_check(prefix: 'gimp', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp is vulnerable in Debian 3.1.\nUpgrade to gimp_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'gimp-data', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp-data is vulnerable in Debian 3.1.\nUpgrade to gimp-data_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'gimp-helpbrowser', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp-helpbrowser is vulnerable in Debian 3.1.\nUpgrade to gimp-helpbrowser_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'gimp-python', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp-python is vulnerable in Debian 3.1.\nUpgrade to gimp-python_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'gimp-svg', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp-svg is vulnerable in Debian 3.1.\nUpgrade to gimp-svg_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'gimp1.2', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp1.2 is vulnerable in Debian 3.1.\nUpgrade to gimp1.2_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'libgimp2.0', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgimp2.0 is vulnerable in Debian 3.1.\nUpgrade to libgimp2.0_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'libgimp2.0-dev', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgimp2.0-dev is vulnerable in Debian 3.1.\nUpgrade to libgimp2.0-dev_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'libgimp2.0-doc', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgimp2.0-doc is vulnerable in Debian 3.1.\nUpgrade to libgimp2.0-doc_2.2.6-1sarge1\n');
}
if (deb_check(prefix: 'gimp', release: '3.1', reference: '2.2.6-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gimp is vulnerable in Debian sarge.\nUpgrade to gimp_2.2.6-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
