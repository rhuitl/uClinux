# This script was automatically generated from the dsa-594
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been identified in the Apache 1.3 webserver:
    "Crazy Einstein" has discovered a vulnerability in the
    "mod_include" module, which can cause a buffer to be overflown and
    could lead to the execution of arbitrary code.
    Larry Cashdollar has discovered a potential buffer overflow in the
    htpasswd utility, which could be exploited when user-supplied is
    passed to the program via a CGI (or PHP, or ePerl, ...) program.
For the stable distribution (woody) these problems have been fixed in
version 1.3.26-0woody6.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.33-2.
We recommend that you upgrade your apache packages.


Solution : http://www.debian.org/security/2004/dsa-594
Risk factor : High';

if (description) {
 script_id(15729);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "594");
 script_cve_id("CVE-2004-0940");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA594] DSA-594-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-594-1 apache");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.0.\nUpgrade to apache_1.3.26-0woody6\n');
}
if (deb_check(prefix: 'apache-common', release: '3.0', reference: '1.3.26-0woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 3.0.\nUpgrade to apache-common_1.3.26-0woody6\n');
}
if (deb_check(prefix: 'apache-dev', release: '3.0', reference: '1.3.26-0woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 3.0.\nUpgrade to apache-dev_1.3.26-0woody6\n');
}
if (deb_check(prefix: 'apache-doc', release: '3.0', reference: '1.3.26-0woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-doc is vulnerable in Debian 3.0.\nUpgrade to apache-doc_1.3.26-0woody6\n');
}
if (deb_check(prefix: 'apache', release: '3.1', reference: '1.3.33-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.1.\nUpgrade to apache_1.3.33-2\n');
}
if (deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian woody.\nUpgrade to apache_1.3.26-0woody6\n');
}
if (w) { security_hole(port: 0, data: desc); }
