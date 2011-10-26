# This script was automatically generated from the dsa-727
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Mark Martinec and Robert Lewis discovered a buffer overflow in
Convert::UUlib, a Perl interface to the uulib library, which may
result in the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 0.201-2woody1.
For the testing (sarge) and unstable (sid) distributions this problem
has been fixed in version 1.0.5.1-1.
We recommend that you upgrade your libconvert-uulib-perl package.


Solution : http://www.debian.org/security/2005/dsa-727
Risk factor : High';

if (description) {
 script_id(18514);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "727");
 script_cve_id("CVE-2005-1349");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA727] DSA-727-1 libconvert-uulib-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-727-1 libconvert-uulib-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libconvert-uulib-perl', release: '3.0', reference: '0.201-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libconvert-uulib-perl is vulnerable in Debian 3.0.\nUpgrade to libconvert-uulib-perl_0.201-2woody1\n');
}
if (deb_check(prefix: 'libconvert-uulib-perl', release: '3.0', reference: '0.201-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libconvert-uulib-perl is vulnerable in Debian woody.\nUpgrade to libconvert-uulib-perl_0.201-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
