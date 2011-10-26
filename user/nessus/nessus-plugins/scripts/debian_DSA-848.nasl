# This script was automatically generated from the dsa-848
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jens Steube discovered two vulnerabilities in masqmail, a mailer for
hosts without permanent internet connection.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    When sending failed mail messages, the address is not sanitised,
    which allows a local attacker to execute arbitrary commands as the
    mail user.
    When opening the log file, masqmail does not relinquish
    privileges, which allows a local attacker to overwrite arbitrary
    files via a symlink attack.
For the old stable distribution (woody) these problems have been fixed in
version 0.1.16-2.2.
For the stable distribution (sarge) these problems have been fixed in
version 0.2.20-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.2.20-1sarge1.
We recommend that you upgrade your masqmail package.


Solution : http://www.debian.org/security/2005/dsa-848
Risk factor : High';

if (description) {
 script_id(19956);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "848");
 script_cve_id("CVE-2005-2662", "CVE-2005-2663");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA848] DSA-848-1 masqmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-848-1 masqmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'masqmail', release: '', reference: '0.2.20-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package masqmail is vulnerable in Debian .\nUpgrade to masqmail_0.2.20-1sarge1\n');
}
if (deb_check(prefix: 'masqmail', release: '3.0', reference: '0.1.16-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package masqmail is vulnerable in Debian 3.0.\nUpgrade to masqmail_0.1.16-2.2\n');
}
if (deb_check(prefix: 'masqmail', release: '3.1', reference: '0.2.20-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package masqmail is vulnerable in Debian 3.1.\nUpgrade to masqmail_0.2.20-1sarge1\n');
}
if (deb_check(prefix: 'masqmail', release: '3.1', reference: '0.2.20-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package masqmail is vulnerable in Debian sarge.\nUpgrade to masqmail_0.2.20-1sarge1\n');
}
if (deb_check(prefix: 'masqmail', release: '3.0', reference: '0.1.16-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package masqmail is vulnerable in Debian woody.\nUpgrade to masqmail_0.1.16-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
