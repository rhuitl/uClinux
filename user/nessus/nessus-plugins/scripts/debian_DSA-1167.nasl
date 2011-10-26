# This script was automatically generated from the dsa-1167
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in the Apache, the
worlds most popular webserver, which may lead to the execution of arbitrary
web script.  The Common Vulnerabilities and Exposures project identifies
the following problems:
   A cross-site scripting (XSS) flaw exists in the mod_imap component of
   the Apache server.
   Apache does not sanitize the Expect header from an HTTP request when 
   it is reflected back in an error message, which might allow cross-site 
   scripting (XSS) style attacks.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.33-6sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.34-3.
We recommend that you upgrade your apache package.


Solution : http://www.debian.org/security/2006/dsa-1167
Risk factor : High';

if (description) {
 script_id(22709);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1167");
 script_cve_id("CVE-2005-3352", "CVE-2006-3918");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1167] DSA-1167-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1167-1 apache");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'apache', release: '', reference: '1.3.34-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian .\nUpgrade to apache_1.3.34-3\n');
}
if (deb_check(prefix: 'apache', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian 3.1.\nUpgrade to apache_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'apache-common', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-common is vulnerable in Debian 3.1.\nUpgrade to apache-common_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'apache-dbg', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dbg is vulnerable in Debian 3.1.\nUpgrade to apache-dbg_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'apache-dev', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-dev is vulnerable in Debian 3.1.\nUpgrade to apache-dev_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'apache-doc', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-doc is vulnerable in Debian 3.1.\nUpgrade to apache-doc_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'apache-perl', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-perl is vulnerable in Debian 3.1.\nUpgrade to apache-perl_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'apache-ssl', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-ssl is vulnerable in Debian 3.1.\nUpgrade to apache-ssl_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'apache-utils', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache-utils is vulnerable in Debian 3.1.\nUpgrade to apache-utils_1.3.33-6sarge3\n');
}
if (deb_check(prefix: 'libapache-mod-perl', release: '3.1', reference: '1.29.0.3-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-perl is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-perl_1.29.0.3-6sarge3\n');
}
if (deb_check(prefix: 'apache', release: '3.1', reference: '1.3.33-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package apache is vulnerable in Debian sarge.\nUpgrade to apache_1.3.33-6sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
