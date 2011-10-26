# This script was automatically generated from the dsa-1019
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Derek Noonburg has fixed several potential vulnerabilities in xpdf,
the Portable Document Format (PDF) suite, which is also present in
koffice, the KDE Office Suite.
The old stable distribution (woody) does not contain koffice packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-4.sarge.3.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your koffice packages.


Solution : http://www.debian.org/security/2006/dsa-1019
Risk factor : High';

if (description) {
 script_id(22561);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1019");
 script_cve_id("CVE-2006-1244");
 script_bugtraq_id(16748);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1019] DSA-1019-1 koffice");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1019-1 koffice");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'karbon', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package karbon is vulnerable in Debian 3.1.\nUpgrade to karbon_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kchart', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kchart is vulnerable in Debian 3.1.\nUpgrade to kchart_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kformula', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kformula is vulnerable in Debian 3.1.\nUpgrade to kformula_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kivio', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kivio is vulnerable in Debian 3.1.\nUpgrade to kivio_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kivio-data', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kivio-data is vulnerable in Debian 3.1.\nUpgrade to kivio-data_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'koffice', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice is vulnerable in Debian 3.1.\nUpgrade to koffice_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'koffice-data', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-data is vulnerable in Debian 3.1.\nUpgrade to koffice-data_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'koffice-dev', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-dev is vulnerable in Debian 3.1.\nUpgrade to koffice-dev_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'koffice-doc-html', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-doc-html is vulnerable in Debian 3.1.\nUpgrade to koffice-doc-html_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'koffice-libs', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-libs is vulnerable in Debian 3.1.\nUpgrade to koffice-libs_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'koshell', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koshell is vulnerable in Debian 3.1.\nUpgrade to koshell_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kpresenter', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpresenter is vulnerable in Debian 3.1.\nUpgrade to kpresenter_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kspread', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kspread is vulnerable in Debian 3.1.\nUpgrade to kspread_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kugar', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kugar is vulnerable in Debian 3.1.\nUpgrade to kugar_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'kword', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kword is vulnerable in Debian 3.1.\nUpgrade to kword_1.3.5-4.sarge.3\n');
}
if (deb_check(prefix: 'koffice', release: '3.1', reference: '1.3.5-4.sarge.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice is vulnerable in Debian sarge.\nUpgrade to koffice_1.3.5-4.sarge.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
