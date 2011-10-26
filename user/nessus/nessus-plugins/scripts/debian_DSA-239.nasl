# This script was automatically generated from the dsa-239
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
in version 2.2.2-3.2.
The old stable distribution (potato) does not contain KDE packages.
For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.
We recommend that you upgrade your KDE packages.


Solution : http://www.debian.org/security/2003/dsa-239
Risk factor : High';

if (description) {
 script_id(15076);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "239");
 script_cve_id("CVE-2002-1393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA239] DSA-239-1 kdesdk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-239-1 kdesdk");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kapptemplate', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kapptemplate is vulnerable in Debian 3.0.\nUpgrade to kapptemplate_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kbabel', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kbabel is vulnerable in Debian 3.0.\nUpgrade to kbabel_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kbabel-dev', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kbabel-dev is vulnerable in Debian 3.0.\nUpgrade to kbabel-dev_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kdepalettes', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdepalettes is vulnerable in Debian 3.0.\nUpgrade to kdepalettes_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kdesdk', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdesdk is vulnerable in Debian 3.0.\nUpgrade to kdesdk_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kdesdk-doc', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdesdk-doc is vulnerable in Debian 3.0.\nUpgrade to kdesdk-doc_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kdesdk-scripts', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdesdk-scripts is vulnerable in Debian 3.0.\nUpgrade to kdesdk-scripts_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kexample', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kexample is vulnerable in Debian 3.0.\nUpgrade to kexample_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kmtrace', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmtrace is vulnerable in Debian 3.0.\nUpgrade to kmtrace_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kspy', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kspy is vulnerable in Debian 3.0.\nUpgrade to kspy_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kstartperf', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kstartperf is vulnerable in Debian 3.0.\nUpgrade to kstartperf_2.2.2-3.2\n');
}
if (deb_check(prefix: 'poxml', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package poxml is vulnerable in Debian 3.0.\nUpgrade to poxml_2.2.2-3.2\n');
}
if (deb_check(prefix: 'kdesdk', release: '3.0', reference: '2.2.2-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdesdk is vulnerable in Debian woody.\nUpgrade to kdesdk_2.2.2-3.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
