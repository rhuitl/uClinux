# This script was automatically generated from the dsa-236
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
in version 2.2.2-13.woody.6.
The old stable distribution (potato) does not contain KDE packages.
For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.
We recommend that you upgrade your KDE packages.


Solution : http://www.debian.org/security/2003/dsa-236
Risk factor : High';

if (description) {
 script_id(15073);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "236");
 script_cve_id("CVE-2002-1393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA236] DSA-236-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-236-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdelibs-dev', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs-dev is vulnerable in Debian 3.0.\nUpgrade to kdelibs-dev_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'kdelibs3', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3 is vulnerable in Debian 3.0.\nUpgrade to kdelibs3_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'kdelibs3-bin', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3-bin is vulnerable in Debian 3.0.\nUpgrade to kdelibs3-bin_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'kdelibs3-cups', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3-cups is vulnerable in Debian 3.0.\nUpgrade to kdelibs3-cups_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'kdelibs3-doc', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs3-doc is vulnerable in Debian 3.0.\nUpgrade to kdelibs3-doc_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'libarts', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libarts is vulnerable in Debian 3.0.\nUpgrade to libarts_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'libarts-alsa', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libarts-alsa is vulnerable in Debian 3.0.\nUpgrade to libarts-alsa_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'libarts-dev', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libarts-dev is vulnerable in Debian 3.0.\nUpgrade to libarts-dev_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'libkmid', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkmid is vulnerable in Debian 3.0.\nUpgrade to libkmid_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'libkmid-alsa', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkmid-alsa is vulnerable in Debian 3.0.\nUpgrade to libkmid-alsa_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'libkmid-dev', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkmid-dev is vulnerable in Debian 3.0.\nUpgrade to libkmid-dev_2.2.2-13.woody.6\n');
}
if (deb_check(prefix: 'kdelibs', release: '3.0', reference: '2.2.2-13.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdelibs is vulnerable in Debian woody.\nUpgrade to kdelibs_2.2.2-13.woody.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
