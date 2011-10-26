# This script was automatically generated from the dsa-1029
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in libphp-adodb, the \'adodb\'
database abstraction layer for PHP.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Andreas Sandblad discovered that improper user input sanitisation
    results in a potential remote SQL injection vulnerability enabling
    an attacker to compromise applications, access or modify data, or
    exploit vulnerabilities in the underlying database implementation.
    This requires the MySQL root password to be empty.  It is fixed by
    limiting access to the script in question.
    A dynamic code evaluation vulnerability allows remote attackers to
    execute arbitrary PHP functions via the \'do\' parameter.
    Andy Staudacher discovered an SQL injection vulnerability due to
    insufficient input sanitising that allows remote attackers to
    execute arbitrary SQL commands.
    GulfTech Security Research discovered multiple cross-site
    scripting vulnerabilities due to improper user-supplied input
    sanitisation.  Attackers can exploit these vulnerabilities to
    cause arbitrary scripts to be executed in the browser of an
    unsuspecting user\'s machine, or result in the theft of
    cookie-based authentication credentials.
For the old stable distribution (woody) these problems have been fixed in
version 1.51-1.2.
For the stable distribution (sarge) these problems have been fixed in
version 4.52-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 4.72-0.1.
We recommend that you upgrade your libphp-adodb package.


Solution : http://www.debian.org/security/2006/dsa-1029
Risk factor : High';

if (description) {
 script_id(22571);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1029");
 script_cve_id("CVE-2006-0146", "CVE-2006-0147", "CVE-2006-0410", "CVE-2006-0806");
 script_bugtraq_id(16187, 16364, 16720);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1029] DSA-1029-1 libphp-adodb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1029-1 libphp-adodb");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libphp-adodb', release: '', reference: '4.72-0.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libphp-adodb is vulnerable in Debian .\nUpgrade to libphp-adodb_4.72-0.1\n');
}
if (deb_check(prefix: 'libphp-adodb', release: '3.0', reference: '1.51-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libphp-adodb is vulnerable in Debian 3.0.\nUpgrade to libphp-adodb_1.51-1.2\n');
}
if (deb_check(prefix: 'libphp-adodb', release: '3.1', reference: '4.52-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libphp-adodb is vulnerable in Debian 3.1.\nUpgrade to libphp-adodb_4.52-1sarge1\n');
}
if (deb_check(prefix: 'libphp-adodb', release: '3.1', reference: '4.52-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libphp-adodb is vulnerable in Debian sarge.\nUpgrade to libphp-adodb_4.52-1sarge1\n');
}
if (deb_check(prefix: 'libphp-adodb', release: '3.0', reference: '1.51-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libphp-adodb is vulnerable in Debian woody.\nUpgrade to libphp-adodb_1.51-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
