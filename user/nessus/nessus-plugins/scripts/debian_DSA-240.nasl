# This script was automatically generated from the dsa-240
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
in version 2.2.2-2.2.
The old stable distribution (potato) does not contain KDE packages.
For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.
We recommend that you upgrade your KDE packages.


Solution : http://www.debian.org/security/2003/dsa-240
Risk factor : High';

if (description) {
 script_id(15077);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "240");
 script_cve_id("CVE-2002-1393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA240] DSA-240-1 kdegames");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-240-1 kdegames");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kabalone', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kabalone is vulnerable in Debian 3.0.\nUpgrade to kabalone_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kasteroids', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kasteroids is vulnerable in Debian 3.0.\nUpgrade to kasteroids_2.2.2-2.2\n');
}
if (deb_check(prefix: 'katomic', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package katomic is vulnerable in Debian 3.0.\nUpgrade to katomic_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kbackgammon', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kbackgammon is vulnerable in Debian 3.0.\nUpgrade to kbackgammon_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kbattleship', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kbattleship is vulnerable in Debian 3.0.\nUpgrade to kbattleship_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kblackbox', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kblackbox is vulnerable in Debian 3.0.\nUpgrade to kblackbox_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kdecarddecks', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdecarddecks is vulnerable in Debian 3.0.\nUpgrade to kdecarddecks_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kjezz', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kjezz is vulnerable in Debian 3.0.\nUpgrade to kjezz_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kjumpingcube', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kjumpingcube is vulnerable in Debian 3.0.\nUpgrade to kjumpingcube_2.2.2-2.2\n');
}
if (deb_check(prefix: 'klines', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klines is vulnerable in Debian 3.0.\nUpgrade to klines_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kmahjongg', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmahjongg is vulnerable in Debian 3.0.\nUpgrade to kmahjongg_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kmines', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmines is vulnerable in Debian 3.0.\nUpgrade to kmines_2.2.2-2.2\n');
}
if (deb_check(prefix: 'konquest', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konquest is vulnerable in Debian 3.0.\nUpgrade to konquest_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kpat', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpat is vulnerable in Debian 3.0.\nUpgrade to kpat_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kpoker', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpoker is vulnerable in Debian 3.0.\nUpgrade to kpoker_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kreversi', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kreversi is vulnerable in Debian 3.0.\nUpgrade to kreversi_2.2.2-2.2\n');
}
if (deb_check(prefix: 'ksame', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksame is vulnerable in Debian 3.0.\nUpgrade to ksame_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kshisen', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kshisen is vulnerable in Debian 3.0.\nUpgrade to kshisen_2.2.2-2.2\n');
}
if (deb_check(prefix: 'ksirtet', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksirtet is vulnerable in Debian 3.0.\nUpgrade to ksirtet_2.2.2-2.2\n');
}
if (deb_check(prefix: 'ksmiletris', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksmiletris is vulnerable in Debian 3.0.\nUpgrade to ksmiletris_2.2.2-2.2\n');
}
if (deb_check(prefix: 'ksnake', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksnake is vulnerable in Debian 3.0.\nUpgrade to ksnake_2.2.2-2.2\n');
}
if (deb_check(prefix: 'ksokoban', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksokoban is vulnerable in Debian 3.0.\nUpgrade to ksokoban_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kspaceduel', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kspaceduel is vulnerable in Debian 3.0.\nUpgrade to kspaceduel_2.2.2-2.2\n');
}
if (deb_check(prefix: 'ktron', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktron is vulnerable in Debian 3.0.\nUpgrade to ktron_2.2.2-2.2\n');
}
if (deb_check(prefix: 'ktuberling', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktuberling is vulnerable in Debian 3.0.\nUpgrade to ktuberling_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kwin4', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kwin4 is vulnerable in Debian 3.0.\nUpgrade to kwin4_2.2.2-2.2\n');
}
if (deb_check(prefix: 'libkdegames', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkdegames is vulnerable in Debian 3.0.\nUpgrade to libkdegames_2.2.2-2.2\n');
}
if (deb_check(prefix: 'lskat', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lskat is vulnerable in Debian 3.0.\nUpgrade to lskat_2.2.2-2.2\n');
}
if (deb_check(prefix: 'kdegames', release: '3.0', reference: '2.2.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdegames is vulnerable in Debian woody.\nUpgrade to kdegames_2.2.2-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
