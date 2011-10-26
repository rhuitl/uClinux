# This script was automatically generated from the dsa-894
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered several buffer overflows in the RTF import
mechanism of AbiWord, a WYSIWYG word processor based on GTK 2.
Opening a specially crafted RTF file could lead to the execution of
arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 1.0.2+cvs.2002.06.05-1woody3.
For the stable distribution (sarge) these problems have been fixed in
version 2.2.7-3sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 2.4.1-1.
We recommend that you upgrade your abiword package.


Solution : http://www.debian.org/security/2005/dsa-894
Risk factor : High';

if (description) {
 script_id(22760);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "894");
 script_cve_id("CVE-2005-2964", "CVE-2005-2972");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA894] DSA-894-1 abiword");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-894-1 abiword");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'abiword', release: '', reference: '2.4.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword is vulnerable in Debian .\nUpgrade to abiword_2.4.1-1\n');
}
if (deb_check(prefix: 'abiword', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword is vulnerable in Debian 3.0.\nUpgrade to abiword_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (deb_check(prefix: 'abiword-common', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-common is vulnerable in Debian 3.0.\nUpgrade to abiword-common_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (deb_check(prefix: 'abiword-doc', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-doc is vulnerable in Debian 3.0.\nUpgrade to abiword-doc_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (deb_check(prefix: 'abiword-gnome', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-gnome is vulnerable in Debian 3.0.\nUpgrade to abiword-gnome_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (deb_check(prefix: 'abiword-gtk', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-gtk is vulnerable in Debian 3.0.\nUpgrade to abiword-gtk_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (deb_check(prefix: 'abiword-plugins', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-plugins is vulnerable in Debian 3.0.\nUpgrade to abiword-plugins_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (deb_check(prefix: 'xfonts-abi', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-abi is vulnerable in Debian 3.0.\nUpgrade to xfonts-abi_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (deb_check(prefix: 'abiword', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword is vulnerable in Debian 3.1.\nUpgrade to abiword_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword-common', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-common is vulnerable in Debian 3.1.\nUpgrade to abiword-common_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword-doc', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-doc is vulnerable in Debian 3.1.\nUpgrade to abiword-doc_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword-gnome', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-gnome is vulnerable in Debian 3.1.\nUpgrade to abiword-gnome_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword-help', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-help is vulnerable in Debian 3.1.\nUpgrade to abiword-help_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword-plugins', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-plugins is vulnerable in Debian 3.1.\nUpgrade to abiword-plugins_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword-plugins-gnome', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword-plugins-gnome is vulnerable in Debian 3.1.\nUpgrade to abiword-plugins-gnome_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'xfonts-abi', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-abi is vulnerable in Debian 3.1.\nUpgrade to xfonts-abi_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword', release: '3.1', reference: '2.2.7-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword is vulnerable in Debian sarge.\nUpgrade to abiword_2.2.7-3sarge2\n');
}
if (deb_check(prefix: 'abiword', release: '3.0', reference: '1.0.2+cvs.2002.06.05-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abiword is vulnerable in Debian woody.\nUpgrade to abiword_1.0.2+cvs.2002.06.05-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
