# This script was automatically generated from the dsa-872
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered a buffer overflow in the RTF importer of kword,
a word processor for the KDE Office Suite that can lead to the
execution of arbitrary code.
The old stable distribution (woody) does not contain a kword package.
For the stable distribution (sarge) this problem has been fixed in
version 1.3.5-4.sarge.1.
For the unstable distribution (sid) this problem has been fixed in
version 1.3.5-5.
We recommend that you upgrade your kword package.


Solution : http://www.debian.org/security/2005/dsa-872
Risk factor : High';

if (description) {
 script_id(22738);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "872");
 script_cve_id("CVE-2005-2971");
 script_bugtraq_id(15060);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA872] DSA-872-1 koffice");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-872-1 koffice");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'koffice', release: '', reference: '1.3.5-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice is vulnerable in Debian .\nUpgrade to koffice_1.3.5-5\n');
}
if (deb_check(prefix: 'karbon', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package karbon is vulnerable in Debian 3.1.\nUpgrade to karbon_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kchart', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kchart is vulnerable in Debian 3.1.\nUpgrade to kchart_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kformula', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kformula is vulnerable in Debian 3.1.\nUpgrade to kformula_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kivio', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kivio is vulnerable in Debian 3.1.\nUpgrade to kivio_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kivio-data', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kivio-data is vulnerable in Debian 3.1.\nUpgrade to kivio-data_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'koffice', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice is vulnerable in Debian 3.1.\nUpgrade to koffice_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'koffice-data', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-data is vulnerable in Debian 3.1.\nUpgrade to koffice-data_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'koffice-dev', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-dev is vulnerable in Debian 3.1.\nUpgrade to koffice-dev_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'koffice-doc-html', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-doc-html is vulnerable in Debian 3.1.\nUpgrade to koffice-doc-html_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'koffice-libs', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice-libs is vulnerable in Debian 3.1.\nUpgrade to koffice-libs_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'koshell', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koshell is vulnerable in Debian 3.1.\nUpgrade to koshell_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kpresenter', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpresenter is vulnerable in Debian 3.1.\nUpgrade to kpresenter_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kspread', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kspread is vulnerable in Debian 3.1.\nUpgrade to kspread_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kugar', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kugar is vulnerable in Debian 3.1.\nUpgrade to kugar_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'kword', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kword is vulnerable in Debian 3.1.\nUpgrade to kword_1.3.5-4.sarge.1\n');
}
if (deb_check(prefix: 'koffice', release: '3.1', reference: '1.3.5-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package koffice is vulnerable in Debian sarge.\nUpgrade to koffice_1.3.5-4.sarge.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
