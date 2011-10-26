# This script was automatically generated from the dsa-347
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
teapop, a POP-3 server, includes modules for authenticating users
against a PostgreSQL or MySQL database.  These modules do not properly
escape user-supplied strings before using them in SQL queries.  This
vulnerability could be exploited to execute arbitrary SQL code under the
privileges of the database user as which teapop has authenticated.
For the stable distribution (woody) this problem has been fixed in
version 0.3.4-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 0.3.5-2.
We recommend that you update your teapop package.


Solution : http://www.debian.org/security/2003/dsa-347
Risk factor : High';

if (description) {
 script_id(15184);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "347");
 script_cve_id("CVE-2003-0515");
 script_bugtraq_id(8146);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA347] DSA-347-1 teapop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-347-1 teapop");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'teapop', release: '3.0', reference: '0.3.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package teapop is vulnerable in Debian 3.0.\nUpgrade to teapop_0.3.4-1woody2\n');
}
if (deb_check(prefix: 'teapop-mysql', release: '3.0', reference: '0.3.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package teapop-mysql is vulnerable in Debian 3.0.\nUpgrade to teapop-mysql_0.3.4-1woody2\n');
}
if (deb_check(prefix: 'teapop-pgsql', release: '3.0', reference: '0.3.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package teapop-pgsql is vulnerable in Debian 3.0.\nUpgrade to teapop-pgsql_0.3.4-1woody2\n');
}
if (deb_check(prefix: 'teapop', release: '3.1', reference: '0.3.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package teapop is vulnerable in Debian 3.1.\nUpgrade to teapop_0.3.5-2\n');
}
if (deb_check(prefix: 'teapop', release: '3.0', reference: '0.3.4-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package teapop is vulnerable in Debian woody.\nUpgrade to teapop_0.3.4-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
