# This script was automatically generated from the dsa-624
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in zip, the archiver for .zip
files.  When doing recursive folder compression the program did not
check the resulting path length, which would lead to memory being
overwritten.  A malicious person could convince a user to create an
archive containing a specially crafted path name, which could lead to
the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 2.30-5woody2.
For the unstable distribution (sid) this problem has been fixed in
version 2.30-8.
We recommend that you upgrade your zip package.


Solution : http://www.debian.org/security/2005/dsa-624
Risk factor : High';

if (description) {
 script_id(16102);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "624");
 script_cve_id("CVE-2004-1010");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA624] DSA-624-1 zip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-624-1 zip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zip', release: '3.0', reference: '2.30-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zip is vulnerable in Debian 3.0.\nUpgrade to zip_2.30-5woody2\n');
}
if (deb_check(prefix: 'zip', release: '3.1', reference: '2.30-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zip is vulnerable in Debian 3.1.\nUpgrade to zip_2.30-8\n');
}
if (deb_check(prefix: 'zip', release: '3.0', reference: '2.30-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zip is vulnerable in Debian woody.\nUpgrade to zip_2.30-5woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
