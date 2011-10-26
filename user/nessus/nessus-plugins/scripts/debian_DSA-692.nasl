# This script was automatically generated from the dsa-692
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The KDE team fixed a bug in kppp in 2002 which was now discovered to be
exploitable by iDEFENSE.  By opening a sufficiently large number of
file descriptors before executing kppp which is installed setuid root a
local attacker is able to take over privileged file descriptors.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.7.
The testing (sarge) and unstable (sid) distributions are not affected
since KDE 3.2 already contained the correction.
We recommend that you upgrade your kppp package.


Solution : http://www.debian.org/security/2005/dsa-692
Risk factor : High';

if (description) {
 script_id(17299);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "692");
 script_cve_id("CVE-2005-0205");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA692] DSA-692-1 kdenetwork");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-692-1 kdenetwork");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdict', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdict is vulnerable in Debian 3.0.\nUpgrade to kdict_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kit', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kit is vulnerable in Debian 3.0.\nUpgrade to kit_2.2.2-14.7\n');
}
if (deb_check(prefix: 'klisa', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klisa is vulnerable in Debian 3.0.\nUpgrade to klisa_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kmail', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmail is vulnerable in Debian 3.0.\nUpgrade to kmail_2.2.2-14.7\n');
}
if (deb_check(prefix: 'knewsticker', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package knewsticker is vulnerable in Debian 3.0.\nUpgrade to knewsticker_2.2.2-14.7\n');
}
if (deb_check(prefix: 'knode', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package knode is vulnerable in Debian 3.0.\nUpgrade to knode_2.2.2-14.7\n');
}
if (deb_check(prefix: 'korn', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package korn is vulnerable in Debian 3.0.\nUpgrade to korn_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kppp', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kppp is vulnerable in Debian 3.0.\nUpgrade to kppp_2.2.2-14.7\n');
}
if (deb_check(prefix: 'ksirc', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksirc is vulnerable in Debian 3.0.\nUpgrade to ksirc_2.2.2-14.7\n');
}
if (deb_check(prefix: 'ktalkd', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktalkd is vulnerable in Debian 3.0.\nUpgrade to ktalkd_2.2.2-14.7\n');
}
if (deb_check(prefix: 'libkdenetwork1', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkdenetwork1 is vulnerable in Debian 3.0.\nUpgrade to libkdenetwork1_2.2.2-14.7\n');
}
if (deb_check(prefix: 'libmimelib-dev', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmimelib-dev is vulnerable in Debian 3.0.\nUpgrade to libmimelib-dev_2.2.2-14.7\n');
}
if (deb_check(prefix: 'libmimelib1', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmimelib1 is vulnerable in Debian 3.0.\nUpgrade to libmimelib1_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdenetwork', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdenetwork is vulnerable in Debian woody.\nUpgrade to kdenetwork_2.2.2-14.7\n');
}
if (w) { security_hole(port: 0, data: desc); }
