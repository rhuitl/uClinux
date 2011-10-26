# This script was automatically generated from the dsa-764
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in cacti, a round-robin
database (RRD) tool that helps create graphs from database
information.  The Common Vulnerabilities and Exposures Project
identifies the following problems:
    Maciej Piotr Falkiewicz and an anonymous researcher discovered an
    input validation bug that allows an attacker to include arbitrary
    PHP code from remote sites which will allow the execution of
    arbitrary code on the server running cacti.
    Due to missing input validation cacti allows a remote attacker to
    insert arbitrary SQL statements.
    Maciej Piotr Falkiewicz discovered an input validation bug that
    allows an attacker to include arbitrary PHP code from remote sites
    which will allow the execution of arbitrary code on the server
    running cacti.
    Stefan Esser discovered that the update for the above mentioned
    vulnerabilities does not perform proper input validation to
    protect against common attacks.
    Stefan Esser discovered that the update for CVE-2005-1525 allows
    remote attackers to modify session information to gain privileges
    and disable the use of addslashes to protect against SQL
    injection.
For the old stable distribution (woody) these problems have been fixed in
version 0.6.7-2.5.
For the stable distribution (sarge) these problems have been fixed in
version 0.8.6c-7sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 0.8.6f-2.
We recommend that you upgrade your cacti package.


Solution : http://www.debian.org/security/2005/dsa-764
Risk factor : High';

if (description) {
 script_id(19258);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "764");
 script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526", "CVE-2005-2148", "CVE-2005-2149");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA764] DSA-764-1 cacti");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-764-1 cacti");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cacti', release: '', reference: '0.8.6f-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cacti is vulnerable in Debian .\nUpgrade to cacti_0.8.6f-2\n');
}
if (deb_check(prefix: 'cacti', release: '3.0', reference: '0.6.7-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cacti is vulnerable in Debian 3.0.\nUpgrade to cacti_0.6.7-2.5\n');
}
if (deb_check(prefix: 'cacti', release: '3.1', reference: '0.8.6c-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cacti is vulnerable in Debian 3.1.\nUpgrade to cacti_0.8.6c-7sarge2\n');
}
if (deb_check(prefix: 'cacti', release: '3.1', reference: '0.8.6c-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cacti is vulnerable in Debian sarge.\nUpgrade to cacti_0.8.6c-7sarge2\n');
}
if (deb_check(prefix: 'cacti', release: '3.0', reference: '0.6.7-2.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cacti is vulnerable in Debian woody.\nUpgrade to cacti_0.6.7-2.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
