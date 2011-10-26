# This script was automatically generated from the dsa-630
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jeroen van Wolffelaar discovered a problem in lintian, the Debian
package checker.  The program removes the working directory even if it
wasn\'t created at program start, removing an unrelated file or
directory a malicious user inserted via a symlink attack.
For the stable distribution (woody) this problem has been fixed in
version 1.20.17.1.
For the unstable distribution (sid) this problem has been fixed in
version 1.23.6.
We recommend that you upgrade your lintian package.


Solution : http://www.debian.org/security/2005/dsa-630
Risk factor : High';

if (description) {
 script_id(16127);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "630");
 script_cve_id("CVE-2004-1000");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA630] DSA-630-1 lintian");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-630-1 lintian");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lintian', release: '3.0', reference: '1.20.17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lintian is vulnerable in Debian 3.0.\nUpgrade to lintian_1.20.17.1\n');
}
if (deb_check(prefix: 'lintian', release: '3.1', reference: '1.23.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lintian is vulnerable in Debian 3.1.\nUpgrade to lintian_1.23.6\n');
}
if (deb_check(prefix: 'lintian', release: '3.0', reference: '1.20.17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lintian is vulnerable in Debian woody.\nUpgrade to lintian_1.20.17.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
