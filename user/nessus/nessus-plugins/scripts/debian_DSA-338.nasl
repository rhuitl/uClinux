# This script was automatically generated from the dsa-338
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
runlevel [runlevel@raregazz.org] reported that ProFTPD\'s PostgreSQL
authentication module is vulnerable to a SQL injection attack.  This
vulnerability could be exploited by a remote, unauthenticated attacker
to execute arbitrary SQL statements, potentially exposing the
passwords of other users, or to connect to ProFTPD as an arbitrary
user without supplying the correct password.
For the stable distribution (woody) this problem has been fixed in
version 1.2.4+1.2.5rc1-5woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.8-8.
We recommend that you update your proftpd package.


Solution : http://www.debian.org/security/2003/dsa-338
Risk factor : High';

if (description) {
 script_id(15175);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "338");
 script_cve_id("CVE-2003-0500");
 script_bugtraq_id(7974);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA338] DSA-338-1 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-338-1 proftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'proftpd', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd is vulnerable in Debian 3.0.\nUpgrade to proftpd_1.2.4+1.2.5rc1-5woody2\n');
}
if (deb_check(prefix: 'proftpd-common', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-common is vulnerable in Debian 3.0.\nUpgrade to proftpd-common_1.2.4+1.2.5rc1-5woody2\n');
}
if (deb_check(prefix: 'proftpd-doc', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-doc is vulnerable in Debian 3.0.\nUpgrade to proftpd-doc_1.2.4+1.2.5rc1-5woody2\n');
}
if (deb_check(prefix: 'proftpd-ldap', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-ldap is vulnerable in Debian 3.0.\nUpgrade to proftpd-ldap_1.2.4+1.2.5rc1-5woody2\n');
}
if (deb_check(prefix: 'proftpd-mysql', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-mysql is vulnerable in Debian 3.0.\nUpgrade to proftpd-mysql_1.2.4+1.2.5rc1-5woody2\n');
}
if (deb_check(prefix: 'proftpd-pgsql', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-pgsql is vulnerable in Debian 3.0.\nUpgrade to proftpd-pgsql_1.2.4+1.2.5rc1-5woody2\n');
}
if (deb_check(prefix: 'proftpd', release: '3.1', reference: '1.2.8-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd is vulnerable in Debian 3.1.\nUpgrade to proftpd_1.2.8-8\n');
}
if (deb_check(prefix: 'proftpd', release: '3.0', reference: '1.2.4+1.2.5rc1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd is vulnerable in Debian woody.\nUpgrade to proftpd_1.2.4+1.2.5rc1-5woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
