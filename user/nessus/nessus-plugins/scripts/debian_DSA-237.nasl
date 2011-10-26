# This script was automatically generated from the dsa-237
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The KDE team discovered several vulnerabilities in the K Desktop
Environment.  In some instances KDE fails to properly quote parameters
of instructions passed to a command shell for execution.  These
parameters may incorporate data such as URLs, filenames and e-mail
addresses, and this data may be provided remotely to a victim in an
e-mail, a webpage or files on a network filesystem or other untrusted
source.
By carefully crafting such data an attacker might be able to execute
arbitrary commands on a vulnerable system using the victim\'s account and
privileges.  The KDE Project is not aware of any existing exploits of
these vulnerabilities.  The patches also provide better safe guards
and check data from untrusted sources more strictly in multiple
places.
For the current stable distribution (woody), these problems have been fixed
in version 2.2.2-14.6.
The old stable distribution (potato) does not contain KDE packages.
For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.
We recommend that you upgrade your KDE packages.


Solution : http://www.debian.org/security/2003/dsa-237
Risk factor : High';

if (description) {
 script_id(15074);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "237");
 script_cve_id("CVE-2002-1393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA237] DSA-237-1 kdenetwork");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-237-1 kdenetwork");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdict', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdict is vulnerable in Debian 3.0.\nUpgrade to kdict_2.2.2-14.6\n');
}
if (deb_check(prefix: 'kit', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kit is vulnerable in Debian 3.0.\nUpgrade to kit_2.2.2-14.6\n');
}
if (deb_check(prefix: 'klisa', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klisa is vulnerable in Debian 3.0.\nUpgrade to klisa_2.2.2-14.6\n');
}
if (deb_check(prefix: 'kmail', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmail is vulnerable in Debian 3.0.\nUpgrade to kmail_2.2.2-14.6\n');
}
if (deb_check(prefix: 'knewsticker', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package knewsticker is vulnerable in Debian 3.0.\nUpgrade to knewsticker_2.2.2-14.6\n');
}
if (deb_check(prefix: 'knode', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package knode is vulnerable in Debian 3.0.\nUpgrade to knode_2.2.2-14.6\n');
}
if (deb_check(prefix: 'korn', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package korn is vulnerable in Debian 3.0.\nUpgrade to korn_2.2.2-14.6\n');
}
if (deb_check(prefix: 'kppp', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kppp is vulnerable in Debian 3.0.\nUpgrade to kppp_2.2.2-14.6\n');
}
if (deb_check(prefix: 'ksirc', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksirc is vulnerable in Debian 3.0.\nUpgrade to ksirc_2.2.2-14.6\n');
}
if (deb_check(prefix: 'ktalkd', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktalkd is vulnerable in Debian 3.0.\nUpgrade to ktalkd_2.2.2-14.6\n');
}
if (deb_check(prefix: 'libkdenetwork1', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkdenetwork1 is vulnerable in Debian 3.0.\nUpgrade to libkdenetwork1_2.2.2-14.6\n');
}
if (deb_check(prefix: 'libmimelib-dev', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmimelib-dev is vulnerable in Debian 3.0.\nUpgrade to libmimelib-dev_2.2.2-14.6\n');
}
if (deb_check(prefix: 'libmimelib1', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmimelib1 is vulnerable in Debian 3.0.\nUpgrade to libmimelib1_2.2.2-14.6\n');
}
if (deb_check(prefix: 'kdenetwork', release: '3.0', reference: '2.2.2-14.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdenetwork is vulnerable in Debian woody.\nUpgrade to kdenetwork_2.2.2-14.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
