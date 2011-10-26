# This script was automatically generated from the dsa-707
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in MySQL, a popular
database.  The Common Vulnerabilities and Exposures project identifies
the following problems:
    Sergei Golubchik discovered a problem in the access handling for
    similar named databases.  If a user is granted privileges to a
    database with a name containing an underscore ("_"), the user also
    gains privileges to other databases with similar names.
    Stefano Di Paola discovered that MySQL allows remote
    authenticated users with INSERT and DELETE privileges to execute
    arbitrary code by using CREATE FUNCTION to access libc calls.
    Stefano Di Paola discovered that MySQL allows remote authenticated
    users with INSERT and DELETE privileges to bypass library path
    restrictions and execute arbitrary libraries by using INSERT INTO
    to modify the mysql.func table.
   Stefano Di Paola discovered that MySQL uses predictable file names
   when creating temporary tables, which allows local users with
   CREATE TEMPORARY TABLE privileges to overwrite arbitrary files via
   a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.11.
For the unstable distribution (sid) these problems have been fixed in
version 4.0.24-5 of mysql-dfsg and in version 4.1.10a-6 of
mysql-dfsg-4.1.
We recommend that you upgrade your mysql packages.


Solution : http://www.debian.org/security/2005/dsa-707
Risk factor : High';

if (description) {
 script_id(18042);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "707");
 script_cve_id("CVE-2004-0957", "CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 script_bugtraq_id(12781);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA707] DSA-707-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-707-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.11\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.11\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.11\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.11\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.11\n');
}
if (deb_check(prefix: 'mysql', release: '3.1', reference: '4.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian 3.1.\nUpgrade to mysql_4.0\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian woody.\nUpgrade to mysql_3.23.49-8.11\n');
}
if (w) { security_hole(port: 0, data: desc); }
