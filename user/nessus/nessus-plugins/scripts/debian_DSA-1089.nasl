# This script was automatically generated from the dsa-1089
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in freeradius, a
high-performance and highly configurable RADIUS server.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    SuSE researchers have discovered several off-by-one errors may
    allow remote attackers to cause a denial of service and possibly
    execute arbitrary code.
    Due to insufficient input validation it is possible for a remote
    attacker to bypass authentication or cause a denial of service.
The old stable distribution (woody) does not contain this package.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.2-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.0-1.2.
We recommend that you upgrade your freeradius package.


Solution : http://www.debian.org/security/2006/dsa-1089
Risk factor : High';

if (description) {
 script_id(22631);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1089");
 script_cve_id("CVE-2005-4744", "CVE-2006-1354");
 script_bugtraq_id(17171, 17293);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1089] DSA-1089-1 freeradius");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1089-1 freeradius");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freeradius', release: '', reference: '1.1.0-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius is vulnerable in Debian .\nUpgrade to freeradius_1.1.0-1.2\n');
}
if (deb_check(prefix: 'freeradius', release: '3.1', reference: '1.0.2-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius is vulnerable in Debian 3.1.\nUpgrade to freeradius_1.0.2-4sarge1\n');
}
if (deb_check(prefix: 'freeradius-dialupadmin', release: '3.1', reference: '1.0.2-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-dialupadmin is vulnerable in Debian 3.1.\nUpgrade to freeradius-dialupadmin_1.0.2-4sarge1\n');
}
if (deb_check(prefix: 'freeradius-iodbc', release: '3.1', reference: '1.0.2-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-iodbc is vulnerable in Debian 3.1.\nUpgrade to freeradius-iodbc_1.0.2-4sarge1\n');
}
if (deb_check(prefix: 'freeradius-krb5', release: '3.1', reference: '1.0.2-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-krb5 is vulnerable in Debian 3.1.\nUpgrade to freeradius-krb5_1.0.2-4sarge1\n');
}
if (deb_check(prefix: 'freeradius-ldap', release: '3.1', reference: '1.0.2-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-ldap is vulnerable in Debian 3.1.\nUpgrade to freeradius-ldap_1.0.2-4sarge1\n');
}
if (deb_check(prefix: 'freeradius-mysql', release: '3.1', reference: '1.0.2-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius-mysql is vulnerable in Debian 3.1.\nUpgrade to freeradius-mysql_1.0.2-4sarge1\n');
}
if (deb_check(prefix: 'freeradius', release: '3.1', reference: '1.0.2-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freeradius is vulnerable in Debian sarge.\nUpgrade to freeradius_1.0.2-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
