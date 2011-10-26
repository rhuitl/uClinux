# This script was automatically generated from the dsa-320
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ingo Saitz discovered a bug in mikmod whereby a long filename inside
an archive file can overflow a buffer when the archive is being read
by mikmod.
For the stable distribution (woody) this problem has been fixed in
version 3.1.6-4woody3.
For old stable distribution (potato) this problem has been fixed in
version 3.1.6-2potato3.
For the unstable distribution (sid) this problem is fixed in version
3.1.6-6.
We recommend that you update your mikmod package.


Solution : http://www.debian.org/security/2003/dsa-320
Risk factor : High';

if (description) {
 script_id(15157);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "320");
 script_cve_id("CVE-2003-0427");
 script_bugtraq_id(7914);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA320] DSA-320-1 mikmod");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-320-1 mikmod");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mikmod', release: '2.2', reference: '3.1.6-2potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mikmod is vulnerable in Debian 2.2.\nUpgrade to mikmod_3.1.6-2potato3\n');
}
if (deb_check(prefix: 'mikmod', release: '3.0', reference: '3.1.6-4woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mikmod is vulnerable in Debian 3.0.\nUpgrade to mikmod_3.1.6-4woody3\n');
}
if (deb_check(prefix: 'mikmod', release: '3.1', reference: '3.1.6-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mikmod is vulnerable in Debian 3.1.\nUpgrade to mikmod_3.1.6-6\n');
}
if (deb_check(prefix: 'mikmod', release: '3.0', reference: '3.1.6-4woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mikmod is vulnerable in Debian woody.\nUpgrade to mikmod_3.1.6-4woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
