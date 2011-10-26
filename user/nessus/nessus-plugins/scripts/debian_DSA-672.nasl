# This script was automatically generated from the dsa-672
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered that programs linked against xview are
vulnerable to a number of buffer overflows in the XView library.  When
the overflow is triggered in a program which is installed setuid root
a malicious user could perhaps execute arbitrary code as privileged
user.
For the stable distribution (woody) these problems have been fixed in
version 3.2p1.4-16woody2.
For the unstable distribution (sid) these problems have been fixed in
version 3.2p1.4-19.
We recommend that you upgrade your xview packages.


Solution : http://www.debian.org/security/2005/dsa-672
Risk factor : High';

if (description) {
 script_id(16346);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "672");
 script_cve_id("CVE-2005-0076");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA672] DSA-672-1 xview");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-672-1 xview");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'olvwm', release: '3.0', reference: '4.4.3.2p1.4-16woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package olvwm is vulnerable in Debian 3.0.\nUpgrade to olvwm_4.4.3.2p1.4-16woody2\n');
}
if (deb_check(prefix: 'olwm', release: '3.0', reference: '3.2p1.4-16woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package olwm is vulnerable in Debian 3.0.\nUpgrade to olwm_3.2p1.4-16woody2\n');
}
if (deb_check(prefix: 'xview-clients', release: '3.0', reference: '3.2p1.4-16woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xview-clients is vulnerable in Debian 3.0.\nUpgrade to xview-clients_3.2p1.4-16woody2\n');
}
if (deb_check(prefix: 'xview-examples', release: '3.0', reference: '3.2p1.4-16woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xview-examples is vulnerable in Debian 3.0.\nUpgrade to xview-examples_3.2p1.4-16woody2\n');
}
if (deb_check(prefix: 'xviewg', release: '3.0', reference: '3.2p1.4-16woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xviewg is vulnerable in Debian 3.0.\nUpgrade to xviewg_3.2p1.4-16woody2\n');
}
if (deb_check(prefix: 'xviewg-dev', release: '3.0', reference: '3.2p1.4-16woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xviewg-dev is vulnerable in Debian 3.0.\nUpgrade to xviewg-dev_3.2p1.4-16woody2\n');
}
if (deb_check(prefix: 'xview', release: '3.1', reference: '3.2p1.4-19')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xview is vulnerable in Debian 3.1.\nUpgrade to xview_3.2p1.4-19\n');
}
if (deb_check(prefix: 'xview', release: '3.0', reference: '3.2p1.4-16woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xview is vulnerable in Debian woody.\nUpgrade to xview_3.2p1.4-16woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
