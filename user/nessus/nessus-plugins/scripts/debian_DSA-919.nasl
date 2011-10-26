# This script was automatically generated from the dsa-919
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The upstream developer of curl, a multi-protocol file transfer
library, informed us that the former correction to several off-by-one
errors are not sufficient.  For completeness please find the original
bug description below:
Several problems were discovered in libcurl, a multi-protocol file
transfer library.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    A buffer overflow has been discovered in libcurl
    that could allow the execution of arbitrary code.
    Stefan Esser discovered several off-by-one errors that allows
    local users to trigger a buffer overflow and cause a denial of
    service or bypass PHP security restrictions via certain URLs.
For the old stable distribution (woody) these problems have been fixed in
version 7.9.5-1woody2.
For the stable distribution (sarge) these problems have been fixed in
version 7.13.2-2sarge5.  This update also includes a bugfix against
data corruption.
For the unstable distribution (sid) these problems have been fixed in
version 7.15.1-1.
We recommend that you upgrade your libcurl packages.


Solution : http://www.debian.org/security/2005/dsa-919
Risk factor : High';

if (description) {
 script_id(22785);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "919");
 script_cve_id("CVE-2005-3185", "CVE-2005-4077");
 script_bugtraq_id(15102, 15647, 15756);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA919] DSA-919-2 curl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-919-2 curl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'curl', release: '', reference: '7.15.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package curl is vulnerable in Debian .\nUpgrade to curl_7.15.1-1\n');
}
if (deb_check(prefix: 'curl', release: '3.0', reference: '7.9.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package curl is vulnerable in Debian 3.0.\nUpgrade to curl_7.9.5-1woody2\n');
}
if (deb_check(prefix: 'libcurl-dev', release: '3.0', reference: '7.9.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurl-dev is vulnerable in Debian 3.0.\nUpgrade to libcurl-dev_7.9.5-1woody2\n');
}
if (deb_check(prefix: 'libcurl2', release: '3.0', reference: '7.9.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurl2 is vulnerable in Debian 3.0.\nUpgrade to libcurl2_7.9.5-1woody2\n');
}
if (deb_check(prefix: 'curl', release: '3.1', reference: '7.13.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package curl is vulnerable in Debian 3.1.\nUpgrade to curl_7.13.2-2sarge5\n');
}
if (deb_check(prefix: 'libcurl3', release: '3.1', reference: '7.13.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurl3 is vulnerable in Debian 3.1.\nUpgrade to libcurl3_7.13.2-2sarge5\n');
}
if (deb_check(prefix: 'libcurl3-dbg', release: '3.1', reference: '7.13.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurl3-dbg is vulnerable in Debian 3.1.\nUpgrade to libcurl3-dbg_7.13.2-2sarge5\n');
}
if (deb_check(prefix: 'libcurl3-dev', release: '3.1', reference: '7.13.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurl3-dev is vulnerable in Debian 3.1.\nUpgrade to libcurl3-dev_7.13.2-2sarge5\n');
}
if (deb_check(prefix: 'libcurl3-gssapi', release: '3.1', reference: '7.13.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurl3-gssapi is vulnerable in Debian 3.1.\nUpgrade to libcurl3-gssapi_7.13.2-2sarge5\n');
}
if (deb_check(prefix: 'curl', release: '3.1', reference: '7.13.2-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package curl is vulnerable in Debian sarge.\nUpgrade to curl_7.13.2-2sarge5\n');
}
if (deb_check(prefix: 'curl', release: '3.0', reference: '7.9.5-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package curl is vulnerable in Debian woody.\nUpgrade to curl_7.9.5-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
