# This script was automatically generated from the dsa-243
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
For the current stable distribution (woody), these problems have been
fixed in version 2.2.2-8.2.  Please note that we are unable to provide
updated packages for both MIPS architectures since the compilation of
kdemultimedia triggers an internal compiler error on these machines.
The old stable distribution (potato) does not contain KDE packages.
For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.
We recommend that you upgrade your KDE packages.


Solution : http://www.debian.org/security/2003/dsa-243
Risk factor : High';

if (description) {
 script_id(15080);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "243");
 script_cve_id("CVE-2002-1393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA243] DSA-243-1 kdemultimedia");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-243-1 kdemultimedia");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'artsbuilder', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package artsbuilder is vulnerable in Debian 3.0.\nUpgrade to artsbuilder_2.2.2-8.2\n');
}
if (deb_check(prefix: 'kdemultimedia-dev', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdemultimedia-dev is vulnerable in Debian 3.0.\nUpgrade to kdemultimedia-dev_2.2.2-8.2\n');
}
if (deb_check(prefix: 'kmid', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmid is vulnerable in Debian 3.0.\nUpgrade to kmid_2.2.2-8.2\n');
}
if (deb_check(prefix: 'kmidi', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmidi is vulnerable in Debian 3.0.\nUpgrade to kmidi_2.2.2-8.2\n');
}
if (deb_check(prefix: 'kmix', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmix is vulnerable in Debian 3.0.\nUpgrade to kmix_2.2.2-8.2\n');
}
if (deb_check(prefix: 'kscd', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kscd is vulnerable in Debian 3.0.\nUpgrade to kscd_2.2.2-8.2\n');
}
if (deb_check(prefix: 'libarts-mpeglib', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libarts-mpeglib is vulnerable in Debian 3.0.\nUpgrade to libarts-mpeglib_2.2.2-8.2\n');
}
if (deb_check(prefix: 'mpeglib', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mpeglib is vulnerable in Debian 3.0.\nUpgrade to mpeglib_2.2.2-8.2\n');
}
if (deb_check(prefix: 'noatun', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noatun is vulnerable in Debian 3.0.\nUpgrade to noatun_2.2.2-8.2\n');
}
if (deb_check(prefix: 'kdemultimedia', release: '3.0', reference: '2.2.2-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdemultimedia is vulnerable in Debian woody.\nUpgrade to kdemultimedia_2.2.2-8.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
