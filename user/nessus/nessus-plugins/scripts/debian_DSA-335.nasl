# This script was automatically generated from the dsa-335
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
mantis, a PHP/MySQL web based bug tracking system, stores the password
used to access its database in a configuration file which is
world-readable.  This could allow a local attacker to read the
password and gain read/write access to the database.
For the stable distribution (woody) this problem has been fixed in
version 0.17.1-3.
The old stable distribution (potato) does not contain a mantis
package.
For the unstable distribution (sid) this problem is fixed in version
0.17.5-6.
We recommend that you update your mantis package.


Solution : http://www.debian.org/security/2003/dsa-335
Risk factor : High';

if (description) {
 script_id(15172);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "335");
 script_cve_id("CVE-2003-0499");
 script_bugtraq_id(8059);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA335] DSA-335-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-335-1 mantis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mantis', release: '3.0', reference: '0.17.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.0.\nUpgrade to mantis_0.17.1-3\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.17.5-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.1.\nUpgrade to mantis_0.17.5-6\n');
}
if (deb_check(prefix: 'mantis', release: '3.0', reference: '0.17.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian woody.\nUpgrade to mantis_0.17.1-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
