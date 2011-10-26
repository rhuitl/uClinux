# This script was automatically generated from the dsa-1012
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow in the command line argument parsing has been
discovered in unzip, the de-archiver for ZIP files, that could lead to
the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 5.50-1woody6.
For the stable distribution (sarge) this problem has been fixed in
version 5.52-1sarge4.
For the unstable distribution (sid) this problem has been fixed in
version 5.52-7.
We recommend that you upgrade your unzip package.


Solution : http://www.debian.org/security/2006/dsa-1012
Risk factor : High';

if (description) {
 script_id(22554);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1012");
 script_cve_id("CVE-2005-4667");
 script_bugtraq_id(15968);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1012] DSA-1012-1 unzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1012-1 unzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'unzip', release: '', reference: '5.52-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian .\nUpgrade to unzip_5.52-7\n');
}
if (deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian 3.0.\nUpgrade to unzip_5.50-1woody6\n');
}
if (deb_check(prefix: 'unzip', release: '3.1', reference: '5.52-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian 3.1.\nUpgrade to unzip_5.52-1sarge4\n');
}
if (deb_check(prefix: 'unzip', release: '3.1', reference: '5.52-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian sarge.\nUpgrade to unzip_5.52-1sarge4\n');
}
if (deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian woody.\nUpgrade to unzip_5.50-1woody6\n');
}
if (w) { security_hole(port: 0, data: desc); }
