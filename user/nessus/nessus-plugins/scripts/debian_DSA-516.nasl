# This script was automatically generated from the dsa-516
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in the ODBC driver of PostgreSQL,
an object-relational SQL database, descended from POSTGRES.  It is possible
to exploit this problem and crash the surrounding application.  Hence, a
PHP script using php4-odbc can be utilised to crash the surrounding
Apache webserver.  Other parts of postgresql are not affected.
For the stable distribution (woody) this problem has been fixed in
version 7.2.1-2woody5.
For the unstable distribution (sid) this problem has been fixed in
version 07.03.0200-3.
We recommend that you upgrade your postgresql and related package.


Solution : http://www.debian.org/security/2004/dsa-516
Risk factor : High';

if (description) {
 script_id(15353);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "516");
 script_cve_id("CVE-2004-0547");
 script_bugtraq_id(10470);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA516] DSA-516-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-516-1 postgresql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libecpg3', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libecpg3 is vulnerable in Debian 3.0.\nUpgrade to libecpg3_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'libpgperl', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpgperl is vulnerable in Debian 3.0.\nUpgrade to libpgperl_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'libpgsql2', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpgsql2 is vulnerable in Debian 3.0.\nUpgrade to libpgsql2_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'libpgtcl', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpgtcl is vulnerable in Debian 3.0.\nUpgrade to libpgtcl_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'odbc-postgresql', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package odbc-postgresql is vulnerable in Debian 3.0.\nUpgrade to odbc-postgresql_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'pgaccess', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pgaccess is vulnerable in Debian 3.0.\nUpgrade to pgaccess_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'postgresql', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql is vulnerable in Debian 3.0.\nUpgrade to postgresql_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'postgresql-client', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-client is vulnerable in Debian 3.0.\nUpgrade to postgresql-client_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'postgresql-contrib', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-contrib is vulnerable in Debian 3.0.\nUpgrade to postgresql-contrib_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'postgresql-dev', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-dev is vulnerable in Debian 3.0.\nUpgrade to postgresql-dev_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'postgresql-doc', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-doc is vulnerable in Debian 3.0.\nUpgrade to postgresql-doc_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'python-pygresql', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-pygresql is vulnerable in Debian 3.0.\nUpgrade to python-pygresql_7.2.1-2woody5\n');
}
if (deb_check(prefix: 'postgresql', release: '3.1', reference: '07.03.0200-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql is vulnerable in Debian 3.1.\nUpgrade to postgresql_07.03.0200-3\n');
}
if (deb_check(prefix: 'postgresql', release: '3.0', reference: '7.2.1-2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql is vulnerable in Debian woody.\nUpgrade to postgresql_7.2.1-2woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
