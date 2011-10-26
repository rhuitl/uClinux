# This script was automatically generated from the dsa-1145
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in freeradius, a
high-performance RADIUS server, which may lead to SQL injection or denial
of service. The Common Vulnerabilities and Exposures project identifies
the following problems:
    An SQL injection vulnerability has been discovered in the
    rlm_sqlcounter module.
    Multiple buffer overflows have been discovered, allowing denial of
    service.
For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-4sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 1.0.5-1.
We recommend that you upgrade your freeradius packages.


Solution : http://www.debian.org/security/2006/dsa-1145
Risk factor : High';

if (description) {
 script_id(22687);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1145");
 script_cve_id("CVE-2005-4745", "CVE-2005-4746");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1145] DSA-1145-1 freeradius");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1145-1 freeradius");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freeradius', release: '', reference: '1.0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius is vulnerable in Debian .\nUpgrade to freeradius_1.0.5-1\n');
}
if (deb_check(prefix: 'freeradius', release: '3.1', reference: '1.0.2-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius is vulnerable in Debian 3.1.\nUpgrade to freeradius_1.0.2-4sarge3\n');
}
if (deb_check(prefix: 'freeradius-dialupadmin', release: '3.1', reference: '1.0.2-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-dialupadmin is vulnerable in Debian 3.1.\nUpgrade to freeradius-dialupadmin_1.0.2-4sarge3\n');
}
if (deb_check(prefix: 'freeradius-iodbc', release: '3.1', reference: '1.0.2-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-iodbc is vulnerable in Debian 3.1.\nUpgrade to freeradius-iodbc_1.0.2-4sarge3\n');
}
if (deb_check(prefix: 'freeradius-krb5', release: '3.1', reference: '1.0.2-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-krb5 is vulnerable in Debian 3.1.\nUpgrade to freeradius-krb5_1.0.2-4sarge3\n');
}
if (deb_check(prefix: 'freeradius-ldap', release: '3.1', reference: '1.0.2-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-ldap is vulnerable in Debian 3.1.\nUpgrade to freeradius-ldap_1.0.2-4sarge3\n');
}
if (deb_check(prefix: 'freeradius-mysql', release: '3.1', reference: '1.0.2-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-mysql is vulnerable in Debian 3.1.\nUpgrade to freeradius-mysql_1.0.2-4sarge3\n');
}
if (deb_check(prefix: 'freeradius', release: '3.1', reference: '1.0.2-4sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius is vulnerable in Debian sarge.\nUpgrade to freeradius_1.0.2-4sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
