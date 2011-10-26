# This script was automatically generated from the dsa-660
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Raphaël Enrici discovered that the KDE screensaver can crash under
certain local circumstances.  This can be exploited by an attacker
with physical access to the workstation to take over the desktop
session.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.9.
This problem has been fixed upstream in KDE 3.0.5 and is therefore
fixed in the unstable (sid) and testing (sarge) distributions already.
We recommend that you upgrade your kscreensaver package.


Solution : http://www.debian.org/security/2005/dsa-660
Risk factor : High';

if (description) {
 script_id(16262);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "660");
 script_cve_id("CVE-2005-0078");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA660] DSA-660-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-660-1 kdebase");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kate', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kate is vulnerable in Debian 3.0.\nUpgrade to kate_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian 3.0.\nUpgrade to kdebase_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdebase-audiolibs', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-audiolibs is vulnerable in Debian 3.0.\nUpgrade to kdebase-audiolibs_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdebase-dev', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-dev is vulnerable in Debian 3.0.\nUpgrade to kdebase-dev_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdebase-doc', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-doc is vulnerable in Debian 3.0.\nUpgrade to kdebase-doc_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdebase-libs', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-libs is vulnerable in Debian 3.0.\nUpgrade to kdebase-libs_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdewallpapers', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdewallpapers is vulnerable in Debian 3.0.\nUpgrade to kdewallpapers_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdm', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdm is vulnerable in Debian 3.0.\nUpgrade to kdm_2.2.2-14.9\n');
}
if (deb_check(prefix: 'konqueror', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konqueror is vulnerable in Debian 3.0.\nUpgrade to konqueror_2.2.2-14.9\n');
}
if (deb_check(prefix: 'konsole', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konsole is vulnerable in Debian 3.0.\nUpgrade to konsole_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kscreensaver', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kscreensaver is vulnerable in Debian 3.0.\nUpgrade to kscreensaver_2.2.2-14.9\n');
}
if (deb_check(prefix: 'libkonq-dev', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq-dev is vulnerable in Debian 3.0.\nUpgrade to libkonq-dev_2.2.2-14.9\n');
}
if (deb_check(prefix: 'libkonq3', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq3 is vulnerable in Debian 3.0.\nUpgrade to libkonq3_2.2.2-14.9\n');
}
if (deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian woody.\nUpgrade to kdebase_2.2.2-14.9\n');
}
if (w) { security_hole(port: 0, data: desc); }
