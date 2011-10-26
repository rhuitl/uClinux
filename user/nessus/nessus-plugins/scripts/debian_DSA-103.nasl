# This script was automatically generated from the dsa-103
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been found in the globbing code for glibc.
This is the code which is used to glob patterns for filenames and is
commonly used in applications like shells and FTP servers.
This has been fixed in version 2.1.3-20 and we recommend that
you upgrade your libc package immediately.


Solution : http://www.debian.org/security/2002/dsa-103
Risk factor : High';

if (description) {
 script_id(14940);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "103");
 script_cve_id("CVE-2001-0886");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA103] DSA-103-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-103-1 glibc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'glibc-doc', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package glibc-doc is vulnerable in Debian 2.2.\nUpgrade to glibc-doc_2.1.3-20\n');
}
if (deb_check(prefix: 'i18ndata', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i18ndata is vulnerable in Debian 2.2.\nUpgrade to i18ndata_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6 is vulnerable in Debian 2.2.\nUpgrade to libc6_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6-dbg', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-dbg is vulnerable in Debian 2.2.\nUpgrade to libc6-dbg_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6-dev', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-dev is vulnerable in Debian 2.2.\nUpgrade to libc6-dev_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6-pic', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-pic is vulnerable in Debian 2.2.\nUpgrade to libc6-pic_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6-prof', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-prof is vulnerable in Debian 2.2.\nUpgrade to libc6-prof_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6.1', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1 is vulnerable in Debian 2.2.\nUpgrade to libc6.1_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6.1-dbg', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-dbg is vulnerable in Debian 2.2.\nUpgrade to libc6.1-dbg_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6.1-dev', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-dev is vulnerable in Debian 2.2.\nUpgrade to libc6.1-dev_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6.1-pic', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-pic is vulnerable in Debian 2.2.\nUpgrade to libc6.1-pic_2.1.3-20\n');
}
if (deb_check(prefix: 'libc6.1-prof', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-prof is vulnerable in Debian 2.2.\nUpgrade to libc6.1-prof_2.1.3-20\n');
}
if (deb_check(prefix: 'libnss1-compat', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss1-compat is vulnerable in Debian 2.2.\nUpgrade to libnss1-compat_2.1.3-20\n');
}
if (deb_check(prefix: 'locales', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package locales is vulnerable in Debian 2.2.\nUpgrade to locales_2.1.3-20\n');
}
if (deb_check(prefix: 'nscd', release: '2.2', reference: '2.1.3-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nscd is vulnerable in Debian 2.2.\nUpgrade to nscd_2.1.3-20\n');
}
if (w) { security_hole(port: 0, data: desc); }
