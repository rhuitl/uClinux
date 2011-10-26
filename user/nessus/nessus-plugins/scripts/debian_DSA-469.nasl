# This script was automatically generated from the dsa-469
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Primoz Bratanic discovered a bug in libpam-pgsql, a PAM module to
authenticate using a PostgreSQL database.  The library does not escape
all user-supplied data that are sent to the database.  An attacker
could exploit this bug to insert SQL statements.
For the stable distribution (woody) this problem has been fixed in
version 0.5.2-3woody2.
For the unstable distribution (sid) this problem has been fixed in
version 0.5.2-7.1.
We recommend that you upgrade your libpam-pgsql package.


Solution : http://www.debian.org/security/2004/dsa-469
Risk factor : High';

if (description) {
 script_id(15306);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "469");
 script_cve_id("CVE-2004-0366");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA469] DSA-469-1 pam-pgsql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-469-1 pam-pgsql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-pgsql', release: '3.0', reference: '0.5.2-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-pgsql is vulnerable in Debian 3.0.\nUpgrade to libpam-pgsql_0.5.2-3woody2\n');
}
if (deb_check(prefix: 'pam-pgsql', release: '3.1', reference: '0.5.2-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pam-pgsql is vulnerable in Debian 3.1.\nUpgrade to pam-pgsql_0.5.2-7.1\n');
}
if (deb_check(prefix: 'pam-pgsql', release: '3.0', reference: '0.5.2-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pam-pgsql is vulnerable in Debian woody.\nUpgrade to pam-pgsql_0.5.2-3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
