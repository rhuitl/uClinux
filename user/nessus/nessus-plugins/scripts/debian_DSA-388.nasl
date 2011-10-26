# This script was automatically generated from the dsa-388
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were discovered in kdebase:
  KDM in KDE 3.1.3 and earlier does not verify whether the pam_setcred
  function call succeeds, which may allow attackers to gain root
  privileges by triggering error conditions within PAM modules, as
  demonstrated in certain configurations of the MIT pam_krb5 module.
  KDM in KDE 3.1.3 and earlier uses a weak session cookie generation
  algorithm that does not provide 128 bits of entropy, which allows
  attackers to guess session cookies via brute force methods and gain
  access to the user session.
These vulnerabilities are described in the following security
advisory from KDE:
http://www.kde.org/info/security/advisory-20030916-1.txt
For the current stable distribution (woody) these problems have been
fixed in version 4:2.2.2-14.7.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you update your kdebase package.


Solution : http://www.debian.org/security/2003/dsa-388
Risk factor : High';

if (description) {
 script_id(15225);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "388");
 script_cve_id("CVE-2003-0690", "CVE-2003-0692");
 script_bugtraq_id(8635, 8636);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA388] DSA-388-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-388-1 kdebase");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kate', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kate is vulnerable in Debian 3.0.\nUpgrade to kate_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian 3.0.\nUpgrade to kdebase_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdebase-audiolibs', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-audiolibs is vulnerable in Debian 3.0.\nUpgrade to kdebase-audiolibs_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdebase-dev', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-dev is vulnerable in Debian 3.0.\nUpgrade to kdebase-dev_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdebase-doc', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-doc is vulnerable in Debian 3.0.\nUpgrade to kdebase-doc_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdebase-libs', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-libs is vulnerable in Debian 3.0.\nUpgrade to kdebase-libs_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdewallpapers', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdewallpapers is vulnerable in Debian 3.0.\nUpgrade to kdewallpapers_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdm', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdm is vulnerable in Debian 3.0.\nUpgrade to kdm_2.2.2-14.7\n');
}
if (deb_check(prefix: 'konqueror', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konqueror is vulnerable in Debian 3.0.\nUpgrade to konqueror_2.2.2-14.7\n');
}
if (deb_check(prefix: 'konsole', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konsole is vulnerable in Debian 3.0.\nUpgrade to konsole_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kscreensaver', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kscreensaver is vulnerable in Debian 3.0.\nUpgrade to kscreensaver_2.2.2-14.7\n');
}
if (deb_check(prefix: 'libkonq-dev', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq-dev is vulnerable in Debian 3.0.\nUpgrade to libkonq-dev_2.2.2-14.7\n');
}
if (deb_check(prefix: 'libkonq3', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq3 is vulnerable in Debian 3.0.\nUpgrade to libkonq3_2.2.2-14.7\n');
}
if (deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian woody.\nUpgrade to kdebase_2.2.2-14.7\n');
}
if (w) { security_hole(port: 0, data: desc); }
