# This script was automatically generated from the dsa-771
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in pdns, a versatile nameserver
that can lead to a denial of service.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Norbert Sendetzky and Jan de Groot discovered that the LDAP backend
    did not properly escape all queries, allowing it to fail and not
    answer queries anymore.
    Wilco Baan discovered that queries from clients without recursion
    permission can temporarily blank out domains to clients with
    recursion permitted.  This enables outside users to blank out a
    domain temporarily to normal users.
The old stable distribution (woody) does not contain pdns packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.9.17-13sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.9.18-1.
We recommend that you upgrade your pdns package.


Solution : http://www.debian.org/security/2005/dsa-771
Risk factor : High';

if (description) {
 script_id(19336);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "771");
 script_cve_id("CVE-2005-2301", "CVE-2005-2302");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA771] DSA-771-1 pdns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-771-1 pdns");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pdns', release: '', reference: '2.9.18-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns is vulnerable in Debian .\nUpgrade to pdns_2.9.18-1\n');
}
if (deb_check(prefix: 'pdns', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns is vulnerable in Debian 3.1.\nUpgrade to pdns_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-backend-geo', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-backend-geo is vulnerable in Debian 3.1.\nUpgrade to pdns-backend-geo_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-backend-ldap', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-backend-ldap is vulnerable in Debian 3.1.\nUpgrade to pdns-backend-ldap_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-backend-mysql', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-backend-mysql is vulnerable in Debian 3.1.\nUpgrade to pdns-backend-mysql_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-backend-pgsql', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-backend-pgsql is vulnerable in Debian 3.1.\nUpgrade to pdns-backend-pgsql_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-backend-pipe', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-backend-pipe is vulnerable in Debian 3.1.\nUpgrade to pdns-backend-pipe_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-backend-sqlite', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-backend-sqlite is vulnerable in Debian 3.1.\nUpgrade to pdns-backend-sqlite_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-doc', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-doc is vulnerable in Debian 3.1.\nUpgrade to pdns-doc_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-recursor', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-recursor is vulnerable in Debian 3.1.\nUpgrade to pdns-recursor_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns-server', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns-server is vulnerable in Debian 3.1.\nUpgrade to pdns-server_2.9.17-13sarge1\n');
}
if (deb_check(prefix: 'pdns', release: '3.1', reference: '2.9.17-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdns is vulnerable in Debian sarge.\nUpgrade to pdns_2.9.17-13sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
