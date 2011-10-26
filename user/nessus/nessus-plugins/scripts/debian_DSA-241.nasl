# This script was automatically generated from the dsa-241
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
in version 2.2.2-9.2.
The old stable distribution (potato) does not contain KDE packages.
For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.
We recommend that you upgrade your KDE packages.


Solution : http://www.debian.org/security/2003/dsa-241
Risk factor : High';

if (description) {
 script_id(15078);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "241");
 script_cve_id("CVE-2002-1393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA241] DSA-241-1 kdeutils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-241-1 kdeutils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ark', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ark is vulnerable in Debian 3.0.\nUpgrade to ark_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kab', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kab is vulnerable in Debian 3.0.\nUpgrade to kab_2.2.2-9.2\n');
}
if (deb_check(prefix: 'karm', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package karm is vulnerable in Debian 3.0.\nUpgrade to karm_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kcalc', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kcalc is vulnerable in Debian 3.0.\nUpgrade to kcalc_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kcharselect', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kcharselect is vulnerable in Debian 3.0.\nUpgrade to kcharselect_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kdepasswd', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdepasswd is vulnerable in Debian 3.0.\nUpgrade to kdepasswd_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kdf', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdf is vulnerable in Debian 3.0.\nUpgrade to kdf_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kedit', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kedit is vulnerable in Debian 3.0.\nUpgrade to kedit_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kfind', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kfind is vulnerable in Debian 3.0.\nUpgrade to kfind_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kfloppy', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kfloppy is vulnerable in Debian 3.0.\nUpgrade to kfloppy_2.2.2-9.2\n');
}
if (deb_check(prefix: 'khexedit', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package khexedit is vulnerable in Debian 3.0.\nUpgrade to khexedit_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kjots', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kjots is vulnerable in Debian 3.0.\nUpgrade to kjots_2.2.2-9.2\n');
}
if (deb_check(prefix: 'klaptopdaemon', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klaptopdaemon is vulnerable in Debian 3.0.\nUpgrade to klaptopdaemon_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kljettool', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kljettool is vulnerable in Debian 3.0.\nUpgrade to kljettool_2.2.2-9.2\n');
}
if (deb_check(prefix: 'klpq', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klpq is vulnerable in Debian 3.0.\nUpgrade to klpq_2.2.2-9.2\n');
}
if (deb_check(prefix: 'klprfax', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klprfax is vulnerable in Debian 3.0.\nUpgrade to klprfax_2.2.2-9.2\n');
}
if (deb_check(prefix: 'knotes', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package knotes is vulnerable in Debian 3.0.\nUpgrade to knotes_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kpm', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpm is vulnerable in Debian 3.0.\nUpgrade to kpm_2.2.2-9.2\n');
}
if (deb_check(prefix: 'ktimer', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktimer is vulnerable in Debian 3.0.\nUpgrade to ktimer_2.2.2-9.2\n');
}
if (deb_check(prefix: 'kdeutils', release: '3.0', reference: '2.2.2-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdeutils is vulnerable in Debian woody.\nUpgrade to kdeutils_2.2.2-9.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
