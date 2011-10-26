# This script was automatically generated from the dsa-316
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The nethack and slashem packages are vulnerable to a buffer overflow exploited via a
long \'-s\' command line option.  This vulnerability could be used by an
attacker to gain gid \'games\' on a system where nethack is installed.
Additionally, some setgid binaries in the nethack package have
incorrect permissions, which could allow a user who gains gid \'games\'
to replace these binaries, potentially causing other users to execute
malicious code when they run nethack.
Note that slashem does not contain the file permission problem
CVE-2003-0359.
For the stable distribution (woody) these problems have been fixed in
version 3.4.0-3.0woody3.
For the old stable distribution (potato) these problems have been fixed in
version 3.3.0-7potato1.
For the unstable distribution (sid) these problems are fixed in
version 3.4.1-1.
We recommend that you update your nethack package.
For the stable distribution (woody) these problems have been fixed in
version 0.0.6E4F8-4.0woody3.
For the old stable distribution (potato) these problems have been fixed in
version 0.0.5E7-3potato1.
For the unstable distribution (sid) these problems are fixed in
version 0.0.6E4F8-6.
We recommend that you update your slashem package.


Solution : http://www.debian.org/security/2003/dsa-316
Risk factor : High';

if (description) {
 script_id(15153);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "316");
 script_cve_id("CVE-2003-0358", "CVE-2003-0359");
 script_bugtraq_id(6806, 7953);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA316] DSA-316-1 nethack");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-316-1 nethack");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'nethack', release: '2.2', reference: '3.3.0-7potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack is vulnerable in Debian 2.2.\nUpgrade to nethack_3.3.0-7potato1\n');
}
if (deb_check(prefix: 'nethack', release: '3.0', reference: '3.4.0-3.0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack is vulnerable in Debian 3.0.\nUpgrade to nethack_3.4.0-3.0woody3\n');
}
if (deb_check(prefix: 'nethack-common', release: '3.0', reference: '3.4.0-3.0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack-common is vulnerable in Debian 3.0.\nUpgrade to nethack-common_3.4.0-3.0woody3\n');
}
if (deb_check(prefix: 'nethack-gnome', release: '3.0', reference: '3.4.0-3.0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack-gnome is vulnerable in Debian 3.0.\nUpgrade to nethack-gnome_3.4.0-3.0woody3\n');
}
if (deb_check(prefix: 'nethack-qt', release: '3.0', reference: '3.4.0-3.0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack-qt is vulnerable in Debian 3.0.\nUpgrade to nethack-qt_3.4.0-3.0woody3\n');
}
if (deb_check(prefix: 'nethack-x11', release: '3.0', reference: '3.4.0-3.0woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack-x11 is vulnerable in Debian 3.0.\nUpgrade to nethack-x11_3.4.0-3.0woody3\n');
}
if (deb_check(prefix: 'nethack', release: '3.1', reference: '0.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack is vulnerable in Debian 3.1.\nUpgrade to nethack_0.0\n');
}
if (deb_check(prefix: 'nethack', release: '2.2', reference: '0.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack is vulnerable in Debian potato.\nUpgrade to nethack_0.0\n');
}
if (deb_check(prefix: 'nethack', release: '3.0', reference: '0.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nethack is vulnerable in Debian woody.\nUpgrade to nethack_0.0\n');
}
if (w) { security_hole(port: 0, data: desc); }
