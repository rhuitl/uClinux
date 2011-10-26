# This script was automatically generated from the dsa-1132
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Mark Dowd discovered a buffer overflow in the mod_rewrite component of
apache, a versatile high-performance HTTP server.  In some situations a
remote attacker could exploit this to execute arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.54-5sarge1.
For the unstable distribution (sid) this problem will be fixed shortly.
We recommend that you upgrade your apache2 package.


Solution : http://www.debian.org/security/2006/dsa-1132
Risk factor : High';

if (description) {
 script_id(22674);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1132");
 script_cve_id("CVE-2006-3747");
 script_xref(name: "CERT", value: "395412");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1132] DSA-1132-1 apache2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1132-1 apache2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache2', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2 is vulnerable in Debian 3.1.\nUpgrade to apache2_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-common', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-common is vulnerable in Debian 3.1.\nUpgrade to apache2-common_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-doc', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-doc is vulnerable in Debian 3.1.\nUpgrade to apache2-doc_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-mpm-perchild', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-perchild is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-perchild_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-mpm-prefork', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-prefork is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-prefork_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-mpm-threadpool', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-threadpool is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-threadpool_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-mpm-worker', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-mpm-worker is vulnerable in Debian 3.1.\nUpgrade to apache2-mpm-worker_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-prefork-dev', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-prefork-dev is vulnerable in Debian 3.1.\nUpgrade to apache2-prefork-dev_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-threaded-dev', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-threaded-dev is vulnerable in Debian 3.1.\nUpgrade to apache2-threaded-dev_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2-utils', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2-utils is vulnerable in Debian 3.1.\nUpgrade to apache2-utils_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'libapr0', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapr0 is vulnerable in Debian 3.1.\nUpgrade to libapr0_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'libapr0-dev', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapr0-dev is vulnerable in Debian 3.1.\nUpgrade to libapr0-dev_2.0.54-5sarge1\n');
}
if (deb_check(prefix: 'apache2', release: '3.1', reference: '2.0.54-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache2 is vulnerable in Debian sarge.\nUpgrade to apache2_2.0.54-5sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
