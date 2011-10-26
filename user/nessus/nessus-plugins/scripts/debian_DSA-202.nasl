# This script was automatically generated from the dsa-202
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tatsuya Kinoshita discovered that IM, which contains interface
commands and Perl libraries for E-mail and NetNews, creates temporary
files insecurely.
These problems have been fixed in version 141-18.1 for the current
stable distribution (woody), in version 133-2.2 of the old stable
distribution (potato) and in version 141-20 for the unstable
distribution (sid).
We recommend that you upgrade your IM package.


Solution : http://www.debian.org/security/2002/dsa-202
Risk factor : High';

if (description) {
 script_id(15039);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "202");
 script_cve_id("CVE-2002-1395");
 script_bugtraq_id(6307);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA202] DSA-202-1 im");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-202-1 im");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'im', release: '2.2', reference: '133-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package im is vulnerable in Debian 2.2.\nUpgrade to im_133-2.3\n');
}
if (deb_check(prefix: 'im', release: '3.0', reference: '141-18.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package im is vulnerable in Debian 3.0.\nUpgrade to im_141-18.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
