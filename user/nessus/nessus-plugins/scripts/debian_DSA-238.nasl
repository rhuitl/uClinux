# This script was automatically generated from the dsa-238
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
in version 2.2.2-5.2.
The old stable distribution (potato) does not contain KDE packages.
For the unstable distribution (sid), these problems will most probably
not be fixed but new packages for KDE 3.1 for sid are expected for
this year.
We recommend that you upgrade your KDE packages.


Solution : http://www.debian.org/security/2003/dsa-238
Risk factor : High';

if (description) {
 script_id(15075);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "238");
 script_cve_id("CVE-2002-1393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA238] DSA-238-1 kdepim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-238-1 kdepim");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kandy', release: '3.0', reference: '2.2.2-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kandy is vulnerable in Debian 3.0.\nUpgrade to kandy_2.2.2-5.2\n');
}
if (deb_check(prefix: 'kdepim-dev', release: '3.0', reference: '2.2.2-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdepim-dev is vulnerable in Debian 3.0.\nUpgrade to kdepim-dev_2.2.2-5.2\n');
}
if (deb_check(prefix: 'kdepim-libs', release: '3.0', reference: '2.2.2-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdepim-libs is vulnerable in Debian 3.0.\nUpgrade to kdepim-libs_2.2.2-5.2\n');
}
if (deb_check(prefix: 'korganizer', release: '3.0', reference: '2.2.2-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package korganizer is vulnerable in Debian 3.0.\nUpgrade to korganizer_2.2.2-5.2\n');
}
if (deb_check(prefix: 'kpilot', release: '3.0', reference: '2.2.2-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpilot is vulnerable in Debian 3.0.\nUpgrade to kpilot_2.2.2-5.2\n');
}
if (deb_check(prefix: 'kdepim', release: '3.0', reference: '2.2.2-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdepim is vulnerable in Debian woody.\nUpgrade to kdepim_2.2.2-5.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
