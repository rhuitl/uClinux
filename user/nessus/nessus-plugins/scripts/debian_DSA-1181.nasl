# This script was automatically generated from the dsa-1181
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tavis Ormandy from the Google Security Team discovered several
vulnerabilities in gzip, the GNU compression utility. The Common
Vulnerabilities and Exposures project identifies the following problems:
    A null pointer dereference may lead to denial of service if gzip is
    used in an automated manner.
    Missing boundary checks may lead to stack modification, allowing
    execution of arbitrary code.
    A buffer underflow in the pack support code may lead to execution of
    arbitrary code.
    A buffer underflow in the LZH support code may lead to execution of
    arbitrary code.
    An infinite loop may lead to denial of service if gzip is used in
    an automated manner.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-10sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.5-15.
We recommend that you upgrade your gzip package.


Solution : http://www.debian.org/security/2006/dsa-1181
Risk factor : High';

if (description) {
 script_id(22723);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1181");
 script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1181] DSA-1181-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1181-1 gzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gzip', release: '', reference: '1.3.5-15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian .\nUpgrade to gzip_1.3.5-15\n');
}
if (deb_check(prefix: 'gzip', release: '3.1', reference: '1.3.5-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian 3.1.\nUpgrade to gzip_1.3.5-10sarge2\n');
}
if (deb_check(prefix: 'gzip', release: '3.1', reference: '1.3.5-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian sarge.\nUpgrade to gzip_1.3.5-10sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
