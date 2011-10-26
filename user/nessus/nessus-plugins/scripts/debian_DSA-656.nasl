# This script was automatically generated from the dsa-656
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit Team has
discovered that the vdr daemon which is used for video disk recorders
for DVB cards can overwrite arbitrary files.
For the stable distribution (woody) this problem has been fixed in
version 1.0.0-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.6-6.
We recommend that you upgrade your vdr package.


Solution : http://www.debian.org/security/2005/dsa-656
Risk factor : High';

if (description) {
 script_id(16246);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "656");
 script_cve_id("CVE-2005-0071");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA656] DSA-656-1 vdr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-656-1 vdr");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'vdr', release: '3.0', reference: '1.0.0-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vdr is vulnerable in Debian 3.0.\nUpgrade to vdr_1.0.0-1woody2\n');
}
if (deb_check(prefix: 'vdr-daemon', release: '3.0', reference: '1.0.0-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vdr-daemon is vulnerable in Debian 3.0.\nUpgrade to vdr-daemon_1.0.0-1woody2\n');
}
if (deb_check(prefix: 'vdr-kbd', release: '3.0', reference: '1.0.0-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vdr-kbd is vulnerable in Debian 3.0.\nUpgrade to vdr-kbd_1.0.0-1woody2\n');
}
if (deb_check(prefix: 'vdr-lirc', release: '3.0', reference: '1.0.0-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vdr-lirc is vulnerable in Debian 3.0.\nUpgrade to vdr-lirc_1.0.0-1woody2\n');
}
if (deb_check(prefix: 'vdr-rcu', release: '3.0', reference: '1.0.0-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vdr-rcu is vulnerable in Debian 3.0.\nUpgrade to vdr-rcu_1.0.0-1woody2\n');
}
if (deb_check(prefix: 'vdr', release: '3.1', reference: '1.2.6-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vdr is vulnerable in Debian 3.1.\nUpgrade to vdr_1.2.6-6\n');
}
if (deb_check(prefix: 'vdr', release: '3.0', reference: '1.0.0-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vdr is vulnerable in Debian woody.\nUpgrade to vdr_1.0.0-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
