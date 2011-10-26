# This script was automatically generated from the dsa-636
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several insecure uses of temporary files have been discovered in
support scripts in the libc6 package which provides the c library for
a GNU/Linux system.  Trustix developers found that the catchsegv
script uses temporary files insecurely.  Openwall developers
discovered insecure temporary files in the glibcbug script.  These
scripts are vulnerable to a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 2.2.5-11.8.
For the unstable distribution (sid) these problems have been fixed in
version 2.3.2.ds1-20.
We recommend that you upgrade your libc6 package.


Solution : http://www.debian.org/security/2005/dsa-636
Risk factor : High';

if (description) {
 script_id(16150);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "636");
 script_cve_id("CVE-2004-0968");
 script_bugtraq_id(11286);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA636] DSA-636-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-636-1 glibc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'glibc-doc', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package glibc-doc is vulnerable in Debian 3.0.\nUpgrade to glibc-doc_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6 is vulnerable in Debian 3.0.\nUpgrade to libc6_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6-dbg', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-dbg is vulnerable in Debian 3.0.\nUpgrade to libc6-dbg_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6-dev', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-dev is vulnerable in Debian 3.0.\nUpgrade to libc6-dev_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6-dev-sparc64', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-dev-sparc64 is vulnerable in Debian 3.0.\nUpgrade to libc6-dev-sparc64_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6-pic', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-pic is vulnerable in Debian 3.0.\nUpgrade to libc6-pic_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6-prof', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-prof is vulnerable in Debian 3.0.\nUpgrade to libc6-prof_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6-sparc64', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-sparc64 is vulnerable in Debian 3.0.\nUpgrade to libc6-sparc64_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6.1', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1 is vulnerable in Debian 3.0.\nUpgrade to libc6.1_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6.1-dbg', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-dbg is vulnerable in Debian 3.0.\nUpgrade to libc6.1-dbg_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6.1-dev', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-dev is vulnerable in Debian 3.0.\nUpgrade to libc6.1-dev_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6.1-pic', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-pic is vulnerable in Debian 3.0.\nUpgrade to libc6.1-pic_2.2.5-11.8\n');
}
if (deb_check(prefix: 'libc6.1-prof', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-prof is vulnerable in Debian 3.0.\nUpgrade to libc6.1-prof_2.2.5-11.8\n');
}
if (deb_check(prefix: 'locales', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package locales is vulnerable in Debian 3.0.\nUpgrade to locales_2.2.5-11.8\n');
}
if (deb_check(prefix: 'nscd', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nscd is vulnerable in Debian 3.0.\nUpgrade to nscd_2.2.5-11.8\n');
}
if (deb_check(prefix: 'glibc', release: '3.1', reference: '2.3.2.ds1-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package glibc is vulnerable in Debian 3.1.\nUpgrade to glibc_2.3.2.ds1-20\n');
}
if (deb_check(prefix: 'glibc', release: '3.0', reference: '2.2.5-11.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package glibc is vulnerable in Debian woody.\nUpgrade to glibc_2.2.5-11.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
