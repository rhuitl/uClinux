# This script was automatically generated from the dsa-193
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE reports a security vulnerability in the klisa package, that
provides a LAN information service similar to "Network Neighbourhood",
which was discovered by Texonet.  It is possible for a local attacker
to exploit a buffer overflow condition in resLISa, a restricted
version of KLISa.  The vulnerability exists in the parsing of the
LOGNAME environment variable, an overly long value will overwrite the
instruction pointer thereby allowing an attacker to seize control of
the executable.
This problem has been fixed in version 2.2.2-14.2 for the current stable
distribution (woody) and in version 2.2.2-14.3 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn\'t contain a kdenetwork package.
We recommend that you upgrade your klisa package immediately.


Solution : http://www.debian.org/security/2002/dsa-193
Risk factor : High';

if (description) {
 script_id(15030);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "193");
 script_cve_id("CVE-2002-1247");
 script_bugtraq_id(6157);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA193] DSA-193-1 kdenetwork");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-193-1 kdenetwork");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdict', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdict is vulnerable in Debian 3.0.\nUpgrade to kdict_2.2.2-14.2\n');
}
if (deb_check(prefix: 'kit', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kit is vulnerable in Debian 3.0.\nUpgrade to kit_2.2.2-14.2\n');
}
if (deb_check(prefix: 'klisa', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klisa is vulnerable in Debian 3.0.\nUpgrade to klisa_2.2.2-14.2\n');
}
if (deb_check(prefix: 'kmail', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmail is vulnerable in Debian 3.0.\nUpgrade to kmail_2.2.2-14.2\n');
}
if (deb_check(prefix: 'knewsticker', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package knewsticker is vulnerable in Debian 3.0.\nUpgrade to knewsticker_2.2.2-14.2\n');
}
if (deb_check(prefix: 'knode', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package knode is vulnerable in Debian 3.0.\nUpgrade to knode_2.2.2-14.2\n');
}
if (deb_check(prefix: 'korn', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package korn is vulnerable in Debian 3.0.\nUpgrade to korn_2.2.2-14.2\n');
}
if (deb_check(prefix: 'kppp', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kppp is vulnerable in Debian 3.0.\nUpgrade to kppp_2.2.2-14.2\n');
}
if (deb_check(prefix: 'ksirc', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksirc is vulnerable in Debian 3.0.\nUpgrade to ksirc_2.2.2-14.2\n');
}
if (deb_check(prefix: 'ktalkd', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktalkd is vulnerable in Debian 3.0.\nUpgrade to ktalkd_2.2.2-14.2\n');
}
if (deb_check(prefix: 'libkdenetwork1', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkdenetwork1 is vulnerable in Debian 3.0.\nUpgrade to libkdenetwork1_2.2.2-14.2\n');
}
if (deb_check(prefix: 'libmimelib-dev', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmimelib-dev is vulnerable in Debian 3.0.\nUpgrade to libmimelib-dev_2.2.2-14.2\n');
}
if (deb_check(prefix: 'libmimelib1', release: '3.0', reference: '2.2.2-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmimelib1 is vulnerable in Debian 3.0.\nUpgrade to libmimelib1_2.2.2-14.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
