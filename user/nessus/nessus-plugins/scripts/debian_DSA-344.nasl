# This script was automatically generated from the dsa-344
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A directory traversal vulnerability in UnZip 5.50 allows attackers to
bypass a check for relative pathnames ("../") by placing certain invalid
characters between the two "." characters.  The fix which was
implemented in DSA-344-1 may not have protected against all methods of
exploiting this vulnerability.
For the stable distribution (woody) this problem has been fixed in
version 5.50-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 5.50-3.
We recommend that you update your unzip package.


Solution : http://www.debian.org/security/2003/dsa-344
Risk factor : High';

if (description) {
 script_id(15181);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "344");
 script_cve_id("CVE-2003-0282");
 script_bugtraq_id(7550);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA344] DSA-344-2 unzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-344-2 unzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian 3.0.\nUpgrade to unzip_5.50-1woody2\n');
}
if (deb_check(prefix: 'unzip', release: '3.1', reference: '5.50-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian 3.1.\nUpgrade to unzip_5.50-3\n');
}
if (deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian woody.\nUpgrade to unzip_5.50-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
