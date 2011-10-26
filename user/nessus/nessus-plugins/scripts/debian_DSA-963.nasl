# This script was automatically generated from the dsa-963
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
NISCC reported that MyDNS, a DNS server using an SQL database for data
storage, can be tricked into an infinite loop by a remote attacker and
hence cause a denial of service condition.
The old stable distribution (woody) does not contain mydns packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.0-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.0+pre-3.
We recommend that you upgrade your mydns package.


Solution : http://www.debian.org/security/2006/dsa-963
Risk factor : High';

if (description) {
 script_id(22829);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "963");
 script_cve_id("CVE-2006-0351");
 script_bugtraq_id(16431);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA963] DSA-963-1 mydns");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-963-1 mydns");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mydns', release: '', reference: '1.1.0+pre-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mydns is vulnerable in Debian .\nUpgrade to mydns_1.1.0+pre-3\n');
}
if (deb_check(prefix: 'mydns-common', release: '3.1', reference: '1.0.0-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mydns-common is vulnerable in Debian 3.1.\nUpgrade to mydns-common_1.0.0-4sarge1\n');
}
if (deb_check(prefix: 'mydns-mysql', release: '3.1', reference: '1.0.0-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mydns-mysql is vulnerable in Debian 3.1.\nUpgrade to mydns-mysql_1.0.0-4sarge1\n');
}
if (deb_check(prefix: 'mydns-pgsql', release: '3.1', reference: '1.0.0-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mydns-pgsql is vulnerable in Debian 3.1.\nUpgrade to mydns-pgsql_1.0.0-4sarge1\n');
}
if (deb_check(prefix: 'mydns', release: '3.1', reference: '1.0.0-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mydns is vulnerable in Debian sarge.\nUpgrade to mydns_1.0.0-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
