# This script was automatically generated from the dsa-1084
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Niko Tyni discovered a buffer overflow in the processing of network
data in typespeed, a game for testing and improving typing speed, which
could lead to the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.4.1-2.4.
For the stable distribution (sarge) this problem has been fixed in
version 0.4.4-8sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.4.4-10.
We recommend that you upgrade your typespeed packages.


Solution : http://www.debian.org/security/2006/dsa-1084
Risk factor : High';

if (description) {
 script_id(22626);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1084");
 script_cve_id("CVE-2006-1515");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1084] DSA-1084-1 typespeed");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1084-1 typespeed");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'typespeed', release: '', reference: '0.4.4-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian .\nUpgrade to typespeed_0.4.4-10\n');
}
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 3.0.\nUpgrade to typespeed_0.4.1-2.4\n');
}
if (deb_check(prefix: 'typespeed', release: '3.1', reference: '0.4.4-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 3.1.\nUpgrade to typespeed_0.4.4-8sarge1\n');
}
if (deb_check(prefix: 'typespeed', release: '3.1', reference: '0.4.4-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian sarge.\nUpgrade to typespeed_0.4.4-8sarge1\n');
}
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian woody.\nUpgrade to typespeed_0.4.1-2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
