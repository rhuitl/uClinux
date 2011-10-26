# This script was automatically generated from the dsa-803
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in the Apache web server.  When it
is acting as an HTTP proxy, it allows remote attackers to poison the
web cache, bypass web application firewall protection, and conduct
cross-site scripting attacks, which causes Apache to incorrectly
handle and forward the body of the request.
The fix for this bug is contained in the apache-common package which means
that there isn\'t any need for a separate update of the apache-perl and
apache-ssl package.
For the old stable distribution (woody) this problem has been fixed in
version 1.3.26-0woody7.
For the stable distribution (sarge) this problem has been fixed in
version 1.3.33-6sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.3.33-8.
We recommend that you upgrade your Apache package.


Solution : http://www.debian.org/security/2005/dsa-803
Risk factor : High';

if (description) {
 script_id(19610);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "803");
 script_cve_id("CVE-2005-2088");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA803] DSA-803-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-803-1 apache");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache', release: '', reference: '1.3.33-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian .\nUpgrade to apache_1.3.33-8\n');
}
if (deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.0.\nUpgrade to apache_1.3.26-0woody7\n');
}
if (deb_check(prefix: 'apache-common', release: '3.0', reference: '1.3.26-0woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 3.0.\nUpgrade to apache-common_1.3.26-0woody7\n');
}
if (deb_check(prefix: 'apache-dev', release: '3.0', reference: '1.3.26-0woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 3.0.\nUpgrade to apache-dev_1.3.26-0woody7\n');
}
if (deb_check(prefix: 'apache-doc', release: '3.0', reference: '1.3.26-0woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-doc is vulnerable in Debian 3.0.\nUpgrade to apache-doc_1.3.26-0woody7\n');
}
if (deb_check(prefix: 'apache', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.1.\nUpgrade to apache_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache-common', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 3.1.\nUpgrade to apache-common_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache-dbg', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dbg is vulnerable in Debian 3.1.\nUpgrade to apache-dbg_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache-dev', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 3.1.\nUpgrade to apache-dev_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache-doc', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-doc is vulnerable in Debian 3.1.\nUpgrade to apache-doc_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache-perl', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-perl is vulnerable in Debian 3.1.\nUpgrade to apache-perl_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache-ssl', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-ssl is vulnerable in Debian 3.1.\nUpgrade to apache-ssl_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache-utils', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-utils is vulnerable in Debian 3.1.\nUpgrade to apache-utils_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'libapache-mod-perl', release: '3.1', reference: '1.29.0.3-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-perl is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-perl_1.29.0.3-6sarge1\n');
}
if (deb_check(prefix: 'apache', release: '3.1', reference: '1.3.33-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian sarge.\nUpgrade to apache_1.3.33-6sarge1\n');
}
if (deb_check(prefix: 'apache', release: '3.0', reference: '1.3.26-0woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian woody.\nUpgrade to apache_1.3.26-0woody7\n');
}
if (w) { security_hole(port: 0, data: desc); }
