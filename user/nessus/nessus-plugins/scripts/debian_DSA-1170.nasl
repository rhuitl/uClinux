# This script was automatically generated from the dsa-1170
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jürgen Weigert discovered that upon unpacking JAR archives fastjar
from the GNU Compiler Collection does not check the path for included
files and allows to create or overwrite files in upper directories.
For the stable distribution (sarge) this problem has been fixed in
version 3.4.3-13sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 4.1.1-11.
We recommend that you upgrade your fastjar package.


Solution : http://www.debian.org/security/2006/dsa-1170
Risk factor : High';

if (description) {
 script_id(22712);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1170");
 script_cve_id("CVE-2006-3619");
 script_bugtraq_id(15669);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1170] DSA-1170-1 gcc-3.4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1170-1 gcc-3.4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gcc-3.4', release: '', reference: '4.1.1-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcc-3.4 is vulnerable in Debian .\nUpgrade to gcc-3.4_4.1.1-11\n');
}
if (deb_check(prefix: 'cpp-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpp-3.4 is vulnerable in Debian 3.1.\nUpgrade to cpp-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'cpp-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpp-3.4-doc is vulnerable in Debian 3.1.\nUpgrade to cpp-3.4-doc_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'fastjar', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fastjar is vulnerable in Debian 3.1.\nUpgrade to fastjar_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'g77-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package g77-3.4 is vulnerable in Debian 3.1.\nUpgrade to g77-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'g77-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package g77-3.4-doc is vulnerable in Debian 3.1.\nUpgrade to g77-3.4-doc_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gcc-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcc-3.4 is vulnerable in Debian 3.1.\nUpgrade to gcc-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gcc-3.4-base', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcc-3.4-base is vulnerable in Debian 3.1.\nUpgrade to gcc-3.4-base_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gcc-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcc-3.4-doc is vulnerable in Debian 3.1.\nUpgrade to gcc-3.4-doc_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gcc-3.4-hppa64', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcc-3.4-hppa64 is vulnerable in Debian 3.1.\nUpgrade to gcc-3.4-hppa64_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gcj-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcj-3.4 is vulnerable in Debian 3.1.\nUpgrade to gcj-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gij-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gij-3.4 is vulnerable in Debian 3.1.\nUpgrade to gij-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gnat-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnat-3.4 is vulnerable in Debian 3.1.\nUpgrade to gnat-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gnat-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnat-3.4-doc is vulnerable in Debian 3.1.\nUpgrade to gnat-3.4-doc_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gobjc-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gobjc-3.4 is vulnerable in Debian 3.1.\nUpgrade to gobjc-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gpc-2.1-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpc-2.1-3.4 is vulnerable in Debian 3.1.\nUpgrade to gpc-2.1-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gpc-2.1-3.4-doc', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpc-2.1-3.4-doc is vulnerable in Debian 3.1.\nUpgrade to gpc-2.1-3.4-doc_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'lib32gcc1', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lib32gcc1 is vulnerable in Debian 3.1.\nUpgrade to lib32gcc1_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'lib64gcc1', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lib64gcc1 is vulnerable in Debian 3.1.\nUpgrade to lib64gcc1_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libffi3', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libffi3 is vulnerable in Debian 3.1.\nUpgrade to libffi3_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libffi3-dev', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libffi3-dev is vulnerable in Debian 3.1.\nUpgrade to libffi3-dev_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libgcc1', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgcc1 is vulnerable in Debian 3.1.\nUpgrade to libgcc1_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libgcc2', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgcc2 is vulnerable in Debian 3.1.\nUpgrade to libgcc2_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libgcj5', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgcj5 is vulnerable in Debian 3.1.\nUpgrade to libgcj5_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libgcj5-awt', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgcj5-awt is vulnerable in Debian 3.1.\nUpgrade to libgcj5-awt_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libgcj5-common', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgcj5-common is vulnerable in Debian 3.1.\nUpgrade to libgcj5-common_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libgcj5-dev', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgcj5-dev is vulnerable in Debian 3.1.\nUpgrade to libgcj5-dev_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'libgnat-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgnat-3.4 is vulnerable in Debian 3.1.\nUpgrade to libgnat-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'treelang-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package treelang-3.4 is vulnerable in Debian 3.1.\nUpgrade to treelang-3.4_3.4.3-13sarge1\n');
}
if (deb_check(prefix: 'gcc-3.4', release: '3.1', reference: '3.4.3-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcc-3.4 is vulnerable in Debian sarge.\nUpgrade to gcc-3.4_3.4.3-13sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
