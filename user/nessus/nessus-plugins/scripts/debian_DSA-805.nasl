# This script was automatically generated from the dsa-805
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in Apache2, the next generation,
scalable, extendable web server.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Marc Stern discovered an off-by-one error in the mod_ssl
    Certificate Revocation List (CRL) verification callback.  When
    Apache is configured to use a CRL this can be used to cause a
    denial of service.
    A vulnerability has been discovered in the Apache web server.
    When it is acting as an HTTP proxy, it allows remote attackers to
    poison the web cache, bypass web application firewall protection,
    and conduct cross-site scripting attacks, which causes Apache to
    incorrectly handle and forward the body of the request.
    A problem has been discovered in mod_ssl, which provides strong
    cryptography (HTTPS support) for Apache that allows remote
    attackers to bypass access restrictions.
    The byte-range filter in Apache 2.0 allows remote attackers to
    cause a denial of service via an HTTP header with a large Range
    field.
The old stable distribution (woody) does not contain Apache2 packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.54-5.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.54-5.
We recommend that you upgrade your apache2 packages.


Solution : http://www.debian.org/security/2005/dsa-805
Risk factor : High';

if (description) {
 script_id(19612);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "805");
 script_cve_id("CVE-2005-1268", "CVE-2005-2088", "CVE-2005-2700", "CVE-2005-2728");
 script_bugtraq_id(14660);
 script_xref(name: "CERT", value: "744929");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA805] DSA-805-1 apache2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-805-1 apache2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache2', release: '', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2 is vulnerable in Debian .\nUpgrade to apache2_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2 is vulnerable in Debian 3.1.\nUpgrade to apache2_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-common', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-common is vulnerable in Debian 3.1.\nUpgrade to apache2-common_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-doc', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-doc is vulnerable in Debian 3.1.\nUpgrade to apache2-doc_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-mpm-perchild', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-perchild is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-perchild_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-mpm-prefork', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-prefork is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-prefork_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-mpm-threadpool', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-threadpool is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-threadpool_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-mpm-worker', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-worker is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-worker_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-prefork-dev', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-prefork-dev is vulnerable in Debian 3.1.\nUpgrade to apache2-prefork-dev_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-threaded-dev', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-threaded-dev is vulnerable in Debian 3.1.\nUpgrade to apache2-threaded-dev_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2-utils', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-utils is vulnerable in Debian 3.1.\nUpgrade to apache2-utils_2.0.54-5\n');
}
if (deb_check(prefix: 'libapr0', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapr0 is vulnerable in Debian 3.1.\nUpgrade to libapr0_2.0.54-5\n');
}
if (deb_check(prefix: 'libapr0-dev', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapr0-dev is vulnerable in Debian 3.1.\nUpgrade to libapr0-dev_2.0.54-5\n');
}
if (deb_check(prefix: 'apache2', release: '3.1', reference: '2.0.54-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2 is vulnerable in Debian sarge.\nUpgrade to apache2_2.0.54-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
