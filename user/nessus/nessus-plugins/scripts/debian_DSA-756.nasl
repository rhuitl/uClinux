# This script was automatically generated from the dsa-756
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Martijn Brinkers discovered cross-site scripting vulnerabilities
    that allow remote attackers to inject arbitrary web script or HTML
    in the URL and e-mail messages.
    James Bercegay of GulfTech Security discovered a vulnerability in
    the variable handling which could lead to attackers altering other
    people\'s preferences and possibly reading them, writing files at
    any location writable for www-data and cross site scripting.
For the old stable distribution (woody) these problems have been fixed in
version 1.2.6-4.
For the stable distribution (sarge) these problems have been fixed in
version 1.4.4-6sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 1.4.4-6sarge1.
We recommend that you upgrade your squirrelmail package.


Solution : http://www.debian.org/security/2005/dsa-756
Risk factor : High';

if (description) {
 script_id(19196);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "756");
 script_cve_id("CVE-2005-1769", "CVE-2005-2095");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA756] DSA-756-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-756-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squirrelmail', release: '', reference: '1.4.4-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian .\nUpgrade to squirrelmail_1.4.4-6sarge1\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.0.\nUpgrade to squirrelmail_1.2.6-4\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.1.\nUpgrade to squirrelmail_1.4.4-6sarge1\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian sarge.\nUpgrade to squirrelmail_1.4.4-6sarge1\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian woody.\nUpgrade to squirrelmail_1.2.6-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
