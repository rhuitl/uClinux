# This script was automatically generated from the dsa-895
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Masanari Yamamoto discovered incorrect use of environment variables in
uim, a flexible input method collection and library, that could lead
to escalated privileges in setuid/setgid applications linked to
libuim.  Affected in Debian is at least mlterm.
The old stable distribution (woody) does not contain uim packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.4.6final1-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.4.7-2.
We recommend that you upgrade your libuim packages.


Solution : http://www.debian.org/security/2005/dsa-895
Risk factor : High';

if (description) {
 script_id(22761);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "895");
 script_cve_id("CVE-2005-3149");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA895] DSA-895-1 uim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-895-1 uim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'uim', release: '', reference: '0.4.7-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim is vulnerable in Debian .\nUpgrade to uim_0.4.7-2\n');
}
if (deb_check(prefix: 'libuim-dev', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libuim-dev is vulnerable in Debian 3.1.\nUpgrade to libuim-dev_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'libuim-nox-dev', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libuim-nox-dev is vulnerable in Debian 3.1.\nUpgrade to libuim-nox-dev_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'libuim0', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libuim0 is vulnerable in Debian 3.1.\nUpgrade to libuim0_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'libuim0-dbg', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libuim0-dbg is vulnerable in Debian 3.1.\nUpgrade to libuim0-dbg_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'libuim0-nox', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libuim0-nox is vulnerable in Debian 3.1.\nUpgrade to libuim0-nox_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'libuim0-nox-dbg', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libuim0-nox-dbg is vulnerable in Debian 3.1.\nUpgrade to libuim0-nox-dbg_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim is vulnerable in Debian 3.1.\nUpgrade to uim_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-anthy', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-anthy is vulnerable in Debian 3.1.\nUpgrade to uim-anthy_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-applet-gnome', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-applet-gnome is vulnerable in Debian 3.1.\nUpgrade to uim-applet-gnome_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-canna', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-canna is vulnerable in Debian 3.1.\nUpgrade to uim-canna_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-common', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-common is vulnerable in Debian 3.1.\nUpgrade to uim-common_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-fep', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-fep is vulnerable in Debian 3.1.\nUpgrade to uim-fep_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-gtk2.0', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-gtk2.0 is vulnerable in Debian 3.1.\nUpgrade to uim-gtk2.0_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-m17nlib', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-m17nlib is vulnerable in Debian 3.1.\nUpgrade to uim-m17nlib_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-prime', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-prime is vulnerable in Debian 3.1.\nUpgrade to uim-prime_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-skk', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-skk is vulnerable in Debian 3.1.\nUpgrade to uim-skk_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-utils', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-utils is vulnerable in Debian 3.1.\nUpgrade to uim-utils_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim-xim', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim-xim is vulnerable in Debian 3.1.\nUpgrade to uim-xim_0.4.6final1-3sarge1\n');
}
if (deb_check(prefix: 'uim', release: '3.1', reference: '0.4.6final1-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uim is vulnerable in Debian sarge.\nUpgrade to uim_0.4.6final1-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
