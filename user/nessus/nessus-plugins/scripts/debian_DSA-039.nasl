# This script was automatically generated from the dsa-039
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'The version of GNU libc that was distributed with Debian
GNU/Linux 2.2 suffered from 2 security problems:


It was possible to use LD_PRELOAD to load libraries that are listed in
/etc/ld.so.cache, even for suid programs. This could be used to create (and
overwrite) files which a user should not be allowed to.
By using LD_PROFILE suid programs would write data to a file to /var/tmp,
which was not done safely. Again, this could be  used to create (and overwrite)
files which a user should not have access to.


Both problems have been fixed in version 2.1.3-17 and we recommend that
you upgrade your glibc packages immediately.

Please note that a side-effect of this upgrade is that ldd will no longer
work on suid programs, unless you logged in as root.



Solution : http://www.debian.org/security/2001/dsa-039
Risk factor : High';

if (description) {
 script_id(14876);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "039");
 script_cve_id("CVE-2001-0169");
 script_bugtraq_id(2223);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA039] DSA-039-1 glibc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-039-1 glibc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'glibc-doc', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package glibc-doc is vulnerable in Debian 2.2.\nUpgrade to glibc-doc_2.1.3-17\n');
}
if (deb_check(prefix: 'i18ndata', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package i18ndata is vulnerable in Debian 2.2.\nUpgrade to i18ndata_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6 is vulnerable in Debian 2.2.\nUpgrade to libc6_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6-dbg', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-dbg is vulnerable in Debian 2.2.\nUpgrade to libc6-dbg_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6-dev', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-dev is vulnerable in Debian 2.2.\nUpgrade to libc6-dev_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6-pic', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-pic is vulnerable in Debian 2.2.\nUpgrade to libc6-pic_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6-prof', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6-prof is vulnerable in Debian 2.2.\nUpgrade to libc6-prof_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6.1', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1 is vulnerable in Debian 2.2.\nUpgrade to libc6.1_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6.1-dbg', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-dbg is vulnerable in Debian 2.2.\nUpgrade to libc6.1-dbg_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6.1-dev', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-dev is vulnerable in Debian 2.2.\nUpgrade to libc6.1-dev_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6.1-pic', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-pic is vulnerable in Debian 2.2.\nUpgrade to libc6.1-pic_2.1.3-17\n');
}
if (deb_check(prefix: 'libc6.1-prof', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc6.1-prof is vulnerable in Debian 2.2.\nUpgrade to libc6.1-prof_2.1.3-17\n');
}
if (deb_check(prefix: 'libnss1-compat', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss1-compat is vulnerable in Debian 2.2.\nUpgrade to libnss1-compat_2.1.3-17\n');
}
if (deb_check(prefix: 'locales', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package locales is vulnerable in Debian 2.2.\nUpgrade to locales_2.1.3-17\n');
}
if (deb_check(prefix: 'nscd', release: '2.2', reference: '2.1.3-17')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nscd is vulnerable in Debian 2.2.\nUpgrade to nscd_2.1.3-17\n');
}
if (w) { security_hole(port: 0, data: desc); }
