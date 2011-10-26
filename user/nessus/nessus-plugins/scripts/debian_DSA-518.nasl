# This script was automatically generated from the dsa-518
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE identified a vulnerability in the Opera web browser that
could be used by remote attackers to create or truncate arbitrary
files on the victims machine.  The KDE team discovered that a similar
vulnerability exists in KDE.
A remote attacker could entice a user to open a carefully crafted
telnet URI which may either create or truncate a file in the victims
home directory.  In KDE 3.2 and later versions the user is first
explicitly asked to confirm the opening of the telnet URI.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-13.woody.10.
We recommend that you upgrade your KDE libraries.


Solution : http://www.debian.org/security/2004/dsa-518
Risk factor : High';

if (description) {
 script_id(15355);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "518");
 script_cve_id("CVE-2004-0411");
 script_bugtraq_id(10358);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA518] DSA-518-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-518-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdelibs-dev', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs-dev is vulnerable in Debian 3.0.\nUpgrade to kdelibs-dev_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'kdelibs3', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3 is vulnerable in Debian 3.0.\nUpgrade to kdelibs3_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'kdelibs3-bin', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3-bin is vulnerable in Debian 3.0.\nUpgrade to kdelibs3-bin_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'kdelibs3-cups', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3-cups is vulnerable in Debian 3.0.\nUpgrade to kdelibs3-cups_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'kdelibs3-doc', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3-doc is vulnerable in Debian 3.0.\nUpgrade to kdelibs3-doc_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'libarts', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libarts is vulnerable in Debian 3.0.\nUpgrade to libarts_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'libarts-alsa', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libarts-alsa is vulnerable in Debian 3.0.\nUpgrade to libarts-alsa_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'libarts-dev', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libarts-dev is vulnerable in Debian 3.0.\nUpgrade to libarts-dev_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'libkmid', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkmid is vulnerable in Debian 3.0.\nUpgrade to libkmid_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'libkmid-alsa', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkmid-alsa is vulnerable in Debian 3.0.\nUpgrade to libkmid-alsa_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'libkmid-dev', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkmid-dev is vulnerable in Debian 3.0.\nUpgrade to libkmid-dev_2.2.2-13.woody.10\n');
}
if (deb_check(prefix: 'kdelibs', release: '3.0', reference: '2.2.2-13.woody.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs is vulnerable in Debian woody.\nUpgrade to kdelibs_2.2.2-13.woody.10\n');
}
if (w) { security_hole(port: 0, data: desc); }
