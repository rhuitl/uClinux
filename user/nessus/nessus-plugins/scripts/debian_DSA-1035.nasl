# This script was automatically generated from the dsa-1035
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp from the Debian Security Audit project discovered that
a cronjob contained in fcheck, a file integrity checker, creates
a temporary file in an insecure fashion.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.7.59-7sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.7.59-8.
We recommend that you upgrade your fcheck package.


Solution : http://www.debian.org/security/2006/dsa-1035
Risk factor : High';

if (description) {
 script_id(22577);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1035");
 script_cve_id("CVE-2006-1753");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1035] DSA-1035-1 fcheck");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1035-1 fcheck");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fcheck', release: '', reference: '2.7.59-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fcheck is vulnerable in Debian .\nUpgrade to fcheck_2.7.59-8\n');
}
if (deb_check(prefix: 'fcheck', release: '3.1', reference: '2.7.59-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fcheck is vulnerable in Debian 3.1.\nUpgrade to fcheck_2.7.59-7sarge1\n');
}
if (deb_check(prefix: 'fcheck', release: '3.1', reference: '2.7.59-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fcheck is vulnerable in Debian sarge.\nUpgrade to fcheck_2.7.59-7sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
